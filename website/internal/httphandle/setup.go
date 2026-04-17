package httphandle

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	jt "github.com/MicahParks/jsontype"
	"github.com/MicahParks/templater"

	"github.com/MicahParks/jwkset/website/internal/httphandle/constant"
)

// DevDecider is a jsontype.Config that determines if the application is in development mode.
type DevDecider interface {
	DevMode() bool
}

// SetupArgs are the arguments for setting up the application.
type SetupArgs struct {
	Static    embed.FS
	Templates embed.FS
}

// SetupResults are the results of setting up the application.
type SetupResults[C jt.Defaulter[C]] struct {
	Conf      C
	Files     http.FileSystem
	Logger    *slog.Logger
	Templater templater.Templater
}

// Setup sets up the application.
func Setup[C jt.Defaulter[C]](args SetupArgs) (SetupResults[C], error) {
	var r SetupResults[C]

	conf, err := jt.Read[C]()
	if err != nil {
		return r, fmt.Errorf("failed to read configuration: %w", err)
	}
	r.Conf = conf

	devMode := true
	d, ok := any(conf).(DevDecider)
	if ok {
		devMode = d.DevMode()
	}

	var logger *slog.Logger
	var tmplr templater.Templater
	var files http.FileSystem
	logLevel := slog.LevelInfo
	if devMode {
		logLevel = slog.LevelDebug
	}
	logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	if devMode {
		tmplr = templater.NewDiskTemplater("templates", nil, "*.gohtml", "")
		files = http.Dir(constant.StaticDir)
	} else {
		tmplr, err = templater.NewEmbeddedTemplater("templates", args.Templates, nil, "*.gohtml", "")
		if err != nil {
			return r, fmt.Errorf("failed to create embedded templater: %w", err)
		}
		sub, err := fs.Sub(args.Static, constant.StaticDir)
		if err != nil {
			return r, fmt.Errorf("failed to create embedded static file system: %w", err)
		}
		files = http.FS(sub)
	}

	r.Files = files
	r.Logger = logger
	r.Templater = tmplr

	return r, nil
}
