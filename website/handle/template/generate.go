package template

import (
	"net/http"

	hh "github.com/MicahParks/httphandle"
	"github.com/MicahParks/httphandle/middleware"

	jsc "github.com/MicahParks/jwkset/website"
	"github.com/MicahParks/jwkset/website/server"
)

type GenerateData struct {
	WrapperData *server.WrapperData
}

type Generate struct {
	s server.Server
}

func (i *Generate) ApplyMiddleware(h http.Handler) http.Handler {
	cache := middleware.CreateCacheControl(middleware.CacheDefaults)
	return cache(middleware.EncodeGzip(h))
}
func (i *Generate) Authorize(_ http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request, skipTemplate bool) {
	return true, r, false
}
func (i *Generate) Initialize(s server.Server) error {
	i.s = s
	return nil
}
func (i *Generate) Respond(r *http.Request) (meta hh.TemplateRespMeta, templateData any, wrapperData hh.WrapperData) {
	w := i.s.WrapperData(r)
	w.Title = "Generate - JWK Set"
	w.Description = "Generate a new JSON Web Key Set or make one from existing PEM encoded keys."
	tData := GenerateData{}
	tData.WrapperData = w
	return meta, tData, w
}
func (i *Generate) TemplateName() string {
	return "generate.gohtml"
}
func (i *Generate) URLPattern() string {
	return jsc.PathGenerate
}
func (i *Generate) WrapperTemplateName() string {
	return jsc.TemplateWrapper
}
