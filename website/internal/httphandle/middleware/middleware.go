// Package middleware provides middleware used by httphandle.
package middleware

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MicahParks/jwkset/website/internal/httphandle/api"
	"github.com/MicahParks/jwkset/website/internal/httphandle/constant"
	"github.com/MicahParks/jwkset/website/internal/httphandle/middleware/ctxkey"
)

const (
	// DefaultTimeout is the default timeout for the context.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxReqSize is the default maximum request size.
	DefaultMaxReqSize = 10 * 1024 * 1024 // 10 MB
	// FieldKeyMethod is the key for the HTTP method.
	FieldKeyMethod = "method"
	// FieldKeyReqUUID is the key for the request UUID.
	FieldKeyReqUUID = "reqUUID"
	// FieldKeyURL is the key for the URL.
	FieldKeyURL = "url"
)

var (
	// GlobalDefaults are the default options for global middleware.
	GlobalDefaults = GlobalOptions{
		MaxReqSize: DefaultMaxReqSize,
		ReqTimeout: DefaultTimeout,
	}
	// CacheDefaults are the default options for cache middleware.
	CacheDefaults = CacheControlOptions{
		MaxAge:  30 * time.Minute,
		NoCache: false,
		NoStore: false,
		Public:  true,
	}
	// CacheControlStatic is the default Cache-Control middleware.
	CacheControlStatic = CreateCacheControl(CacheDefaults)
)

// Middleware is a function that returns a wrapped handler.
type Middleware func(next http.Handler) http.Handler

// GlobalOptions are the options for global middleware.
type GlobalOptions struct {
	MaxReqSize uint32
	ReqTimeout time.Duration
}

// ApplyGlobal applies global middleware to a handler.
func ApplyGlobal(h http.Handler, l *slog.Logger, options GlobalOptions) http.Handler {
	return Wrap(h, CreateAddLogger(l), RequestUUID, CreateAddCtx(options.ReqTimeout), CreateLimitReqSize(int64(options.MaxReqSize)))
}

// Wrap wraps a handler with multiple middleware. The middleware is applied in the order it is passed in.
func Wrap(handler http.Handler, middleware ...Middleware) http.Handler {
	for _, m := range middleware {
		handler = m(handler)
	}
	return handler
}

// CreateAddCtx creates a middleware that adds a context to the request.
func CreateAddCtx(timeout time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx, cancel := context.WithTimeout(ctx, timeout)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
			cancel()
		})
	}
}

// CreateAddLogger creates a middleware that adds a logger to the request.
func CreateAddLogger(l *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			reqUUID := ctx.Value(ctxkey.ReqUUID).(uuid.UUID)
			logger := l.With( // Better to have short declaration than reassignment.
				FieldKeyMethod, r.Method,
				FieldKeyReqUUID, reqUUID.String(),
				FieldKeyURL, r.URL.String(),
			)
			ctx = context.WithValue(ctx, ctxkey.Logger, logger)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

type CacheControlOptions struct {
	MaxAge  time.Duration
	NoCache bool
	NoStore bool
	Public  bool
}

// CreateCacheControl creates a middleware that adds a Cache-Control header to the response.
func CreateCacheControl(options CacheControlOptions) Middleware {
	ma := options.MaxAge.Milliseconds()
	if ma > 1000 {
		ma /= 1000
	} else {
		ma = 0
	}
	var b strings.Builder
	b.WriteString("max-age=")
	b.WriteString(strconv.FormatInt(ma, 10))
	b.WriteString(", must-revalidate, ")
	if options.NoCache {
		b.WriteString("no-cache, ")
	}
	if options.NoStore {
		b.WriteString("no-store, ")
	}
	if options.Public {
		b.WriteString("public")
	} else {
		b.WriteString("private")
	}
	headerValue := b.String()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			writer.Header().Set(constant.HeaderCacheControl, headerValue)
			next.ServeHTTP(writer, req)
		})
	}
}

// CreateLimitReqSize creates a middleware that limits the size of a request.
func CreateLimitReqSize(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
			req.Body = http.MaxBytesReader(writer, req.Body, maxBytes)
			next.ServeHTTP(writer, req)
		})
	}
}

// EncodeGzip is a middleware that encodes the response body with gzip if the client accepts it.
func EncodeGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get(constant.HeaderAcceptEncoding), constant.ContentEncodingGzip) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set(constant.HeaderContentEncoding, constant.ContentEncodingGzip)
		gz := gzip.NewWriter(w)
		//goland:noinspection GoUnhandledErrorResult
		defer func() {
			err := gz.Close()
			if err != nil {
				slog.Default().ErrorContext(r.Context(), "Failed to close gzip writer.",
					constant.LogErr, err,
				)
			}
		}()

		gzw := gzipResponseWriter{
			ResponseWriter: w,
			writer:         gz,
		}
		next.ServeHTTP(gzw, r)
	})
}

// RequestUUID is a middleware that adds a request UUID to the request.
func RequestUUID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		reqUUID, _ := uuid.NewRandom()
		ctx = context.WithValue(ctx, ctxkey.ReqUUID, reqUUID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// WriteErrorBody writes an error body to the response writer.
func WriteErrorBody(ctx context.Context, code int, message string, writer http.ResponseWriter) {
	data, err := json.Marshal(api.NewAPIError(ctx, code, message))
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.Header().Set(constant.HeaderContentType, constant.ContentTypeJSON)
	writer.WriteHeader(code)
	_, _ = writer.Write(data)
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}
