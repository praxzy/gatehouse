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

	"github.com/praxzy/gatehouse/backend/internal/auth"

	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

const defaultHTTPAddress = ":8080"

func main() {
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

	cookieSecure, err := sessionCookieSecure()
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: address,
		Handler: httpapi.NewRouter(
			httpapi.Dependencies{
				Authentication: authentication,
				SessionCookie: httpapi.NewSessionCookie(
					cookieSecure,
				),
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
	value := os.Getenv("SESSION_COOKIE_SECURE")
	if value == "" {
		return true, nil
	}

	secure, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf(
			"parse SESSION_COOKIE_SECURE: %w",
			err,
		)
	}

	return secure, nil
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
