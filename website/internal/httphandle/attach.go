// Package httphandle contains reusable code for creating HTTP servers.
package httphandle

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MicahParks/templater"
	"github.com/google/uuid"

	"github.com/MicahParks/jwkset/website/internal/httphandle/constant"
	"github.com/MicahParks/jwkset/website/internal/httphandle/middleware"
	"github.com/MicahParks/jwkset/website/internal/httphandle/middleware/ctxkey"
)

// AttachArgs are the arguments for attaching handlers to a mux.
type AttachArgs[A AppSpecific] struct {
	API            []API[A]
	Files          http.FileSystem
	MiddlewareOpts middleware.GlobalOptions
	Template       []Template[A]
	Templater      templater.Templater
}

// Attach attaches the handlers to the mux.
func Attach[A AppSpecific](args AttachArgs[A], a A, mux *http.ServeMux) error {
	l := a.Logger()

	for _, handler := range args.API {
		h, err := createAPIHandler(handler, a)
		if err != nil {
			return fmt.Errorf("failed to create an API handler %q: %w", handler.URLPattern(), err)
		}
		h = handler.ApplyMiddleware(h)
		h = middleware.ApplyGlobal(h, l, args.MiddlewareOpts)
		mux.Handle(handler.URLPattern(), h)
	}

	for _, handler := range args.Template {
		err := handler.Initialize(a)
		if err != nil {
			return fmt.Errorf("failed to initialize template handler %q: %w", handler.TemplateName(), err)
		}
		var h http.Handler
		if handler.URLPattern() == constant.PathIndex {
			h = createIndexTemplateHandler(a, args, handler)
		} else {
			h = handler.ApplyMiddleware(h)
			h = createTemplateHandler(a, args, handler)
		}
		h = middleware.ApplyGlobal(h, l, args.MiddlewareOpts)
		mux.Handle(handler.URLPattern(), h)
	}

	return nil
}

func ExecuteTemplate(args TemplateArgs, tmplr templater.Templater) error {
	ctx := args.Request.Context()

	buf := &strings.Builder{}
	err := tmplr.Tmpl().ExecuteTemplate(buf, args.Name, args.Data)
	if err != nil {
		return fmt.Errorf("failed to template data: %w", err)
	}

	result := TemplateDataResult{
		InnerHTML:    template.HTML(buf.String()),
		RequestUUID:  ctx.Value(ctxkey.ReqUUID).(uuid.UUID),
		TemplateArgs: args,
	}

	headerAddName := args.Name + constant.TemplateHeaderAddExtension
	headerAdd := tmplr.Tmpl().Lookup(headerAddName)
	if headerAdd != nil {
		buf.Reset()
		err = headerAdd.ExecuteTemplate(buf, headerAddName, args.Data)
		if err != nil {
			return fmt.Errorf("failed to template HeaderAdd data: %w", err)
		}
		result.HeaderAdd = template.HTML(buf.String())
	}

	wData := args.WrapperData
	wData.SetResult(result)

	if args.ResponseCode == 0 {
		args.ResponseCode = http.StatusOK
	}
	args.Writer.WriteHeader(args.ResponseCode)
	err = tmplr.Tmpl().ExecuteTemplate(args.Writer, args.WrapperName, wData)
	if err != nil {
		return fmt.Errorf("failed to template wrapper data: %w", err)
	}

	return nil
}

func createAPIHandler[A AppSpecific](handler API[A], i A) (http.Handler, error) {
	err := handler.Initialize(i)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize API handler %q: %w", handler.URLPattern(), err)
	}
	reqContentType, respContentType := handler.ContentType()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != handler.HTTPMethod() {
			middleware.WriteErrorBody(ctx, http.StatusMethodNotAllowed, fmt.Sprintf("Expected %s.", handler.HTTPMethod()), w)
			return
		}
		if r.Header.Get(constant.HeaderContentType) != reqContentType {
			middleware.WriteErrorBody(ctx, http.StatusUnsupportedMediaType, fmt.Sprintf("Expected %s.", reqContentType), w)
			return
		}
		authorized, r := handler.Authorize(w, r)
		if !authorized {
			return
		}

		code, body, err := handler.Respond(r)
		if err != nil {
			// API handlers shouldn't return errors, so theoretically this should never run.
			l := r.Context().Value(ctxkey.Logger).(*slog.Logger)
			l.Error("Failed to handle API request.",
				constant.LogErr, err,
			)
			middleware.WriteErrorBody(ctx, http.StatusInternalServerError, "Unexpected handler error.", w)
			return
		}

		if respContentType != "" {
			w.Header().Set(constant.HeaderContentType, respContentType)
		}
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}), nil
}

func createTemplateHandler[A AppSpecific](a A, attachArgs AttachArgs[A], handler Template[A]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		l := ctx.Value(ctxkey.Logger).(*slog.Logger)

		authorized, r, skipTemplate := handler.Authorize(w, r)
		if !authorized {
			if !skipTemplate {
				a.ErrorTemplate(metaFromCode(http.StatusUnauthorized), r, w)
			}
			return
		}

		meta, tData, wData := handler.Respond(r)

		for _, cookie := range meta.Cookies {
			http.SetCookie(w, cookie)
		}

		switch meta.ResponseCode {
		case 0:
			meta.ResponseCode = http.StatusOK
		case http.StatusOK:
			// Do nothing.
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusNotModified, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			http.Redirect(w, r, meta.RedirectURL, meta.ResponseCode)
			return
		case http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError:
			l.Warn("Failed to handle template request.",
				constant.LogRespCode, meta.ResponseCode,
			)
			a.ErrorTemplate(meta, r, w)
			return
		default:
			l.Warn("Unexpected response code.",
				constant.LogRespCode, meta.ResponseCode,
			)
			// Proceed.
		}

		args := TemplateArgs{
			Data:         tData,
			Name:         handler.TemplateName(),
			Request:      r,
			ResponseCode: meta.ResponseCode,
			WrapperData:  wData,
			WrapperName:  handler.WrapperTemplateName(),
			Writer:       w,
		}
		executeTemplate(a, args, attachArgs.Templater)
	})
}

func createIndexTemplateHandler[A AppSpecific](a A, attachArgs AttachArgs[A], handler Template[A]) http.Handler {
	fileServer := middleware.CacheControlStatic(middleware.EncodeGzip(http.FileServer(attachArgs.Files)))
	h := handler.ApplyMiddleware(createTemplateHandler(a, attachArgs, handler))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != constant.PathIndex {
			f, err := attachArgs.Files.Open(r.URL.Path)
			if err != nil {
				a.NotFound(w, r)
				return
			}
			//goland:noinspection GoUnhandledErrorResult
			defer f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func executeTemplate[A AppSpecific](a A, args TemplateArgs, tmplr templater.Templater) {
	err := ExecuteTemplate(args, tmplr)
	if err != nil {
		l := args.Request.Context().Value(ctxkey.Logger).(*slog.Logger)
		l.Error("Failed to template JS data.",
			constant.LogErr, err,
		)
		a.ErrorTemplate(metaFromCode(http.StatusInternalServerError), args.Request, args.Writer)
	}
}

func metaFromCode(code int) TemplateRespMeta {
	meta := TemplateRespMeta{
		ResponseCode: code,
	}
	return meta
}
