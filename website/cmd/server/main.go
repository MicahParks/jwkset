package main

import (
	"context"
	"log"
	"net/http"
	"time"

	hh "github.com/MicahParks/httphandle"
	hhconst "github.com/MicahParks/httphandle/constant"
	"github.com/MicahParks/httphandle/middleware"

	jsc "github.com/MicahParks/jwkset/website"
	"github.com/MicahParks/jwkset/website/handle/api"
	"github.com/MicahParks/jwkset/website/handle/template"
	"github.com/MicahParks/jwkset/website/server"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupArgs := hh.SetupArgs{
		Static:    jsc.Static,
		Templates: jsc.Templates,
	}
	conf, err := hh.Setup[jsc.Config](setupArgs)
	if err != nil {
		log.Fatalf(hhconst.LogFmt, "Failed to setup.", err)
	}
	l := conf.Logger

	srv := server.NewServer(conf.Conf, l)

	apiHandlers := []hh.API[server.Server]{
		&api.Inspect{},
		&api.NewGen{},
		&api.PemGen{},
	}
	templateHandlers := []hh.Template[server.Server]{
		&template.Index{},
		&template.Generate{},
		&template.Inspect{},
	}
	attachArgs := hh.AttachArgs[server.Server]{
		API:            apiHandlers,
		Files:          conf.Files,
		MiddlewareOpts: middleware.GlobalDefaults,
		Template:       templateHandlers,
		Templater:      conf.Templater,
	}

	mux := http.NewServeMux()
	err = hh.Attach(attachArgs, srv, mux)
	if err != nil {
		l.ErrorContext(ctx, "Failed to attach handlers.",
			hhconst.LogErr, err,
		)
		return
	}

	l.InfoContext(ctx, "Starting server.",
		"devClick", "http://localhost:8080",
	)
	serveArgs := hh.ServeArgs{
		Logger:          l.With("httphandle", true),
		Port:            8080,
		ShutdownFunc:    srv.Shutdown,
		ShutdownTimeout: 5 * time.Second,
	}
	hh.Serve(serveArgs, mux)
}
