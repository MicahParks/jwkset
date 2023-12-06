package server

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	hh "github.com/MicahParks/httphandle"
	hhconst "github.com/MicahParks/httphandle/constant"
	"github.com/MicahParks/recaptcha"

	jsc "github.com/MicahParks/jwkset/website"
)

type NavItem struct {
	Active bool
	Name   string
	Href   string
}

type WrapperData struct {
	Link             jsc.Link
	Path             jsc.Path
	NavItems         []NavItem
	ReCAPTCHASiteKey string
	Result           hh.TemplateDataResult
	Title            string
	Description      string
}

func (w *WrapperData) SetResult(result hh.TemplateDataResult) {
	w.Result = result
}

type Server struct {
	Conf     jsc.Config
	Verifier recaptcha.VerifierV3
	l        *slog.Logger
}

func NewServer(conf jsc.Config, l *slog.Logger) Server {
	verifier := recaptcha.NewVerifierV3(conf.ReCAPTCHA.Secret, recaptcha.VerifierV3Options{})
	return Server{
		Conf:     conf,
		l:        l,
		Verifier: verifier,
	}
}

func (s Server) ErrorTemplate(meta hh.TemplateRespMeta, r *http.Request, w http.ResponseWriter) {
	s.l.ErrorContext(r.Context(), "Failed to execute template.")
}
func (s Server) Logger() *slog.Logger {
	return s.l
}
func (s Server) NotFound(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, hhconst.PathIndex, http.StatusFound)
}
func (s Server) Shutdown(_ context.Context) error {
	return nil
}
func (s Server) WrapperData(r *http.Request) *WrapperData {
	navItems := []NavItem{
		{
			Name: "Home",
			Href: hhconst.PathIndex,
		},
		{
			Name: "Generate",
			Href: jsc.PathGenerate,
		},
		{
			Name: "Inspect",
			Href: jsc.PathInspect,
		},
		{
			Name: "GitHub",
			Href: jsc.LinkGitHub,
		},
	}
	for i := range navItems {
		if navItems[i].Href == hhconst.PathIndex {
			if r.URL.Path == "/" {
				navItems[i].Active = true
			}
		} else if strings.HasPrefix(r.URL.Path, navItems[i].Href) {
			navItems[i].Active = true
		}
	}
	return &WrapperData{
		ReCAPTCHASiteKey: s.Conf.ReCAPTCHA.SiteKey,
		Result:           hh.TemplateDataResult{},
		NavItems:         navItems,
	}
}
