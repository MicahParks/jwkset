package api

import (
	"log/slog"
	"net/http"

	"github.com/MicahParks/httphandle/api"
	hhconst "github.com/MicahParks/httphandle/constant"
	"github.com/MicahParks/httphandle/middleware/ctxkey"
	"github.com/MicahParks/recaptcha"

	"github.com/MicahParks/jwkset/website/server"
)

func authReCAPTCHA(action string, s server.Server, w http.ResponseWriter, r *http.Request) (bool, *http.Request) {
	if s.Conf.ReCAPTCHA.SiteKey == "" {
		return true, r
	}
	ctx := r.Context()
	l := ctx.Value(ctxkey.Logger).(*slog.Logger)
	token := r.Header.Get("g-recaptcha-response")
	resp, err := s.Verifier.Verify(ctx, token, "")
	if err != nil {
		l.InfoContext(ctx, "Failed to verify reCAPTCHA response.",
			hhconst.LogErr, err,
		)
		return api.AuthorizeError(ctx, http.StatusUnauthorized, "reCAPTCHA verification failed.", w)
	}
	options := recaptcha.V3ResponseCheckOptions{
		Action:   []string{action},
		Hostname: s.Conf.ReCAPTCHA.Hostname,
		Score:    s.Conf.ReCAPTCHA.ScoreMin,
	}
	err = resp.Check(options)
	if err != nil {
		l.InfoContext(ctx, "Failed reCAPTCHA response check.",
			hhconst.LogErr, err,
		)
		return false, r
	}
	return true, r
}
