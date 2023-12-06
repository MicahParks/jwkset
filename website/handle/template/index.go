package template

import (
	"net/http"

	hh "github.com/MicahParks/httphandle"
	hhconst "github.com/MicahParks/httphandle/constant"
	"github.com/MicahParks/httphandle/middleware"

	jsc "github.com/MicahParks/jwkset/website"
	"github.com/MicahParks/jwkset/website/server"
)

type IndexData struct {
	WrapperData *server.WrapperData
}

type Index struct {
	s server.Server
}

func (i *Index) ApplyMiddleware(h http.Handler) http.Handler {
	cache := middleware.CreateCacheControl(middleware.CacheDefaults)
	return cache(middleware.EncodeGzip(h))
}
func (i *Index) Authorize(_ http.ResponseWriter, r *http.Request) (authorized bool, modified *http.Request, skipTemplate bool) {
	return true, r, false
}
func (i *Index) Initialize(s server.Server) error {
	i.s = s
	return nil
}
func (i *Index) Respond(req *http.Request) (meta hh.TemplateRespMeta, templateData any, wrapperData hh.WrapperData) {
	w := i.s.WrapperData(req)
	w.Title = "Home - JWK Set"
	w.Description = "A website for JSON Web Key Sets. Generate and inspect JSON Web Keys. Compatible with PEM encoded assets."
	tData := IndexData{}
	tData.WrapperData = w
	return meta, tData, w
}
func (i *Index) TemplateName() string {
	return "index.gohtml"
}
func (i *Index) URLPattern() string {
	return hhconst.PathIndex
}
func (i *Index) WrapperTemplateName() string {
	return jsc.TemplateWrapper
}
