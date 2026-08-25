package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/praxzy/gatehouse/examples/employee-portal/internal/config"
	"github.com/praxzy/gatehouse/examples/employee-portal/internal/httpapp"
	"github.com/praxzy/gatehouse/examples/employee-portal/internal/oidcclient"
	"github.com/praxzy/gatehouse/examples/employee-portal/internal/session"
)

func main() {
	configuration, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("load employee portal configuration", "error", err)
		os.Exit(1)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}
	oidc, err := oidcclient.New(
		configuration.Issuer,
		configuration.ClientID,
		configuration.ClientSecret,
		configuration.RedirectURI,
		httpClient,
	)
	if err != nil {
		slog.Error("create OIDC client", "error", err)
		os.Exit(1)
	}

	application, err := httpapp.New(
		oidc,
		session.NewStore(),
		configuration.SessionCookieSecure,
	)
	if err != nil {
		slog.Error("create employee portal", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              configuration.HTTPAddress,
		Handler:           application.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer stop()

	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	slog.Info(
		"employee portal listening",
		"address",
		configuration.HTTPAddress,
		"issuer",
		configuration.Issuer,
	)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("serve employee portal", "error", err)
		os.Exit(1)
	}
}
