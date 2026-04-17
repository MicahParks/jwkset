package httphandle

import (
	"html/template"
	"net/http"

	"github.com/google/uuid"
)

// TemplateDataResult is the result of executing a template, used for the wrapper template.
type TemplateDataResult struct {
	HeaderAdd    template.HTML
	InnerHTML    template.HTML
	RequestUUID  uuid.UUID
	TemplateArgs TemplateArgs
}

// TemplateArgs are the arguments passed to the template.
type TemplateArgs struct {
	Data         any
	Name         string
	Request      *http.Request
	ResponseCode int
	WrapperData  WrapperData
	WrapperName  string
	Writer       http.ResponseWriter
}

// TemplateRespMeta is the metadata returned from the template.
type TemplateRespMeta struct {
	Cookies      []*http.Cookie
	RedirectURL  string
	ResponseCode int
}
