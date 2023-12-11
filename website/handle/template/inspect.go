package template

import (
	"net/http"

	hh "github.com/MicahParks/httphandle"
	"github.com/MicahParks/httphandle/middleware"

	jsc "github.com/MicahParks/jwkset/website"
	"github.com/MicahParks/jwkset/website/server"
)

type InspectData struct {
	WrapperData *server.WrapperData
}

type Inspect struct {
	s server.Server
}

func (i *Inspect) ApplyMiddleware(h http.Handler) http.Handler {
	cache := middleware.CreateCacheControl(middleware.CacheDefaults)
	return cache(middleware.EncodeGzip(h))
}
func (i *Inspect) Authorize(_ http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request, skipTemplate bool) {
	return true, r, false
}
func (i *Inspect) Initialize(s server.Server) error {
	i.s = s
	return nil
}
func (i *Inspect) Respond(r *http.Request) (meta hh.TemplateRespMeta, templateData any, wrapperData hh.WrapperData) {
	w := i.s.WrapperData(r)
	w.Title = "Inspect - JWK Set"
	w.Description = "Inspect a JSON Web Key Set validity and extract public and private keys as PKIX and PKCS #8 assets."
	tData := InspectData{}
	tData.WrapperData = w
	return meta, tData, w
}
func (i *Inspect) TemplateName() string {
	return "inspect.gohtml"
}
func (i *Inspect) URLPattern() string {
	return jsc.PathInspect
}
func (i *Inspect) WrapperTemplateName() string {
	return jsc.TemplateWrapper
}
