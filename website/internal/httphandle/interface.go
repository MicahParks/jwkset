package httphandle

import (
	"log/slog"
	"net/http"
)

// API is an interface for an API handler.
type API[A AppSpecific] interface {
	ApplyMiddleware(h http.Handler) http.Handler
	Authorize(w http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request)
	ContentType() (request, response string)
	HTTPMethod() string
	Initialize(A) error
	Respond(r *http.Request) (code int, body []byte, err error)
	URLPattern() string
}

// AppSpecific is an interface for the application specific implementations.
type AppSpecific interface {
	ErrorTemplate(meta TemplateRespMeta, r *http.Request, w http.ResponseWriter)
	Logger() *slog.Logger
	NotFound(w http.ResponseWriter, r *http.Request)
}

// Template is an interface for a template handler.
type Template[A AppSpecific] interface {
	ApplyMiddleware(h http.Handler) http.Handler
	Authorize(w http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request, skipTemplate bool)
	Initialize(A) error
	Respond(r *http.Request) (meta TemplateRespMeta, templateData any, wrapperData WrapperData)
	TemplateName() string
	URLPattern() string
	WrapperTemplateName() string
}

type WrapperData interface {
	SetResult(result TemplateDataResult)
}
