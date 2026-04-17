package httphandle

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/MicahParks/jwkset/website/internal/httphandle/constant"
)

// ServeArgs are the arguments for the Serve function.
type ServeArgs struct {
	Logger          *slog.Logger
	Port            uint16
	ShutdownFunc    func(ctx context.Context) error
	ShutdownTimeout time.Duration
}

// Serve serves the http server and shuts it down gracefully.
func Serve(args ServeArgs, handler http.Handler) {
	srv := &http.Server{
		Addr:    ":" + strconv.FormatUint(uint64(args.Port), 10),
		Handler: handler,
	}

	idleConnsClosed := make(chan struct{})
	go serverShutdown(context.Background(), args, idleConnsClosed, srv)
	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		args.Logger.Info("Failed to listen and serve.",
			constant.LogErr, err,
		)
	}

	select {
	case <-time.After(args.ShutdownTimeout):
		log.Print("Failed to close idle connections before timeout.")
	case <-idleConnsClosed:
	}
}

func serverShutdown(ctx context.Context, args ServeArgs, idleConnsClosed chan struct{}, srv *http.Server) {
	<-ctx.Done()
	args.Logger.InfoContext(ctx, "Context over.",
		constant.LogErr, ctx.Err(),
	)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), args.ShutdownTimeout)
	err := args.ShutdownFunc(shutdownCtx)
	if err != nil {
		args.Logger.ErrorContext(ctx, "Failed to run provided shutdown function.",
			constant.LogErr, err,
		)
	}

	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	if err != nil {
		args.Logger.ErrorContext(ctx, "Couldn't shut down HTTP server before time ended.",
			constant.LogErr, err,
		)
	}

	close(idleConnsClosed)
}
