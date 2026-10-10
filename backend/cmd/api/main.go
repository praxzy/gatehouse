package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/application"
	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
	"github.com/praxzy/gatehouse/backend/internal/observability"
	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

const defaultHTTPAddress = ":8080"

func main() {
	slog.SetDefault(observability.NewJSONLogger(os.Stdout))

	if err := run(); err != nil {
		slog.Error("API stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	address := os.Getenv("HTTP_ADDR")
	if address == "" {
		address = defaultHTTPAddress
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return fmt.Errorf("open database pool: %w", err)
	}
	defer pool.Close()

	pingContext, cancelPing := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer cancelPing()

	if err := pool.Ping(pingContext); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	auditWriter := audit.NewWriter()
	exportService, err := auditExportServiceFromEnvironment(
		context.Background(), pool, auditWriter,
	)
	if err != nil {
		return err
	}

	loginLimiter, err := auth.NewLocalLoginRateLimiter(
		10,
		15*time.Minute,
	)
	if err != nil {
		return fmt.Errorf("create login limiter: %w", err)
	}

	mfaSecretCipher, err := mfaSecretCipherFromEnvironment()
	if err != nil {
		return err
	}

	emailVerificationSender, err :=
		emailVerificationSenderFromEnvironment()
	if err != nil {
		return err
	}

	membershipInvitationSender, err :=
		membershipInvitationSenderFromEnvironment()
	if err != nil {
		return err
	}

	authentication, err := auth.NewService(
		pool,
		loginLimiter,
		auditWriter,
		auth.WithMFASecretCipher(mfaSecretCipher),
		auth.WithEmailVerificationSender(
			emailVerificationSender,
		),
		auth.WithMembershipInvitationSender(
			membershipInvitationSender,
		),
	)
	if err != nil {
		return fmt.Errorf(
			"create authentication service: %w",
			err,
		)
	}

	upstreamFederation, err :=
		upstreamFederationServicesFromEnvironment(
			pool,
			authentication,
			auditWriter,
		)
	if err != nil {
		return err
	}

	applications, err := application.NewService(
		pool,
		auditWriter,
	)
	if err != nil {
		return fmt.Errorf(
			"create application service: %w",
			err,
		)
	}

	oidcProvider, err := oidcProviderFromEnvironment()
	if err != nil {
		return err
	}

	oidcAuthorization, err := oidc.NewAuthorizationService(
		pool,
		auditWriter,
	)
	if err != nil {
		return fmt.Errorf(
			"create OIDC authorization service: %w",
			err,
		)
	}

	oidcTokens, err := oidc.NewTokenService(
		pool,
		oidcProvider,
		auditWriter,
	)
	if err != nil {
		return fmt.Errorf(
			"create OIDC token service: %w",
			err,
		)
	}

	cookieSecure, err := sessionCookieSecure()
	if err != nil {
		return err
	}

	csrfProtector, err := csrfProtectorFromEnvironment()
	if err != nil {
		return err
	}

	rateLimiters, err := httpapi.NewDefaultRouteRateLimiters()
	if err != nil {
		return fmt.Errorf(
			"create route rate limiters: %w",
			err,
		)
	}

	trustProxyHeaders, err := booleanEnvironment(
		"TRUST_PROXY_HEADERS",
		false,
	)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: address,
		Handler: httpapi.NewRouter(
			httpapi.Dependencies{
				Logger:         slog.Default(),
				Authentication: authentication,
				Applications:   applications,
				AuditExports:   exportService,
				OIDCMetadata:   oidcProvider,
				SessionCookie: httpapi.NewSessionCookie(
					cookieSecure,
				),
				OIDCAuthorization:       oidcAuthorization,
				OIDCTokens:              oidcTokens,
				FederationAuthorization: upstreamFederation.authorization,
				FederationCallback:      upstreamFederation.callback,
				FederationManagement:    upstreamFederation.management,
				CSRF:                    csrfProtector,
				RateLimiters:            rateLimiters,
				TrustProxyHeaders:       trustProxyHeaders,
			},
		),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	shutdownSignal, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	if exportService != nil {
		go runAuditExportDispatcher(shutdownSignal, exportService)
	}
	defer stop()

	serverError := make(chan error, 1)

	go func() {
		slog.Info("Gatehouse API listening", "address", address)
		serverError <- server.ListenAndServe()
	}()

	select {
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err

	case <-shutdownSignal.Done():
		shutdownContext, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()

		slog.Info("shutting down Gatehouse API")
		return server.Shutdown(shutdownContext)
	}

}

func sessionCookieSecure() (bool, error) {
	return booleanEnvironment(
		"SESSION_COOKIE_SECURE",
		true,
	)
}

func booleanEnvironment(
	name string,
	defaultValue bool,
) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return defaultValue, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf(
			"parse %s: %w",
			name,
			err,
		)
	}

	return parsed, nil
}

func mfaSecretCipherFromEnvironment() (
	*auth.AESGCMSecretCipher,
	error,
) {
	keyID := strings.TrimSpace(
		os.Getenv("MFA_ENCRYPTION_KEY_ID"),
	)
	encodedKey := strings.TrimSpace(
		os.Getenv("MFA_ENCRYPTION_KEY_BASE64"),
	)

	if keyID == "" || encodedKey == "" {
		return nil, errors.New(
			"MFA encryption key configuration is required",
		)
	}

	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, errors.New(
			"MFA_ENCRYPTION_KEY_BASE64 is invalid",
		)
	}

	secretCipher, err := auth.NewAESGCMSecretCipher(keyID, key)
	if err != nil {
		return nil, fmt.Errorf(
			"create MFA secret cipher: %w",
			err,
		)
	}

	return secretCipher, nil
}
