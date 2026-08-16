package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/praxzy/gatehouse/backend/internal/auth"

	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

type recordingEmailVerificationSender struct {
	deliveries []auth.EmailVerificationDelivery
}

func (sender *recordingEmailVerificationSender) SendEmailVerification(
	_ context.Context,
	delivery auth.EmailVerificationDelivery,
) error {
	sender.deliveries = append(
		sender.deliveries,
		delivery,
	)

	return nil
}

func TestEmailVerificationLifecycle(t *testing.T) {
	ctx := context.Background()
	sender := &recordingEmailVerificationSender{}

	service, pool :=
		newAuthenticationTestServiceWithEmailSender(
			t,
			ctx,
			sender,
		)

	registration, err := service.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Verified Company",
			TenantSlug:  "verified-company",
			Email:       "owner@verified.test",
			DisplayName: "Verified Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register unverified user: %v", err)
	}

	if len(sender.deliveries) != 1 {
		t.Fatalf(
			"expected one verification delivery, got %d",
			len(sender.deliveries),
		)
	}

	delivery := sender.deliveries[0]

	if delivery.RecipientEmail != "owner@verified.test" {
		t.Fatalf(
			"unexpected verification recipient %q",
			delivery.RecipientEmail,
		)
	}

	if delivery.Token == "" {
		t.Fatal("expected non-empty verification token")
	}

	if !delivery.ExpiresAt.After(time.Now()) {
		t.Fatal("expected verification token in the future")
	}

	_, err = service.Login(
		ctx,
		auth.LoginInput{
			Email:    "owner@verified.test",
			Password: "correct horse battery staple",
			ClientIP: "127.0.0.1",
		},
	)
	if !errors.Is(
		err,
		auth.ErrEmailVerificationRequired,
	) {
		t.Fatalf(
			"expected ErrEmailVerificationRequired, got %v",
			err,
		)
	}

	verification, err := service.VerifyEmail(
		ctx,
		delivery.Token,
	)
	if err != nil {
		t.Fatalf("verify email: %v", err)
	}

	if verification.UserID != registration.UserID {
		t.Fatal("verification returned the wrong user")
	}

	if verification.Email != delivery.RecipientEmail {
		t.Fatal("verification returned the wrong email")
	}

	if verification.VerifiedAt.IsZero() {
		t.Fatal("expected verification timestamp")
	}

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM users
			WHERE id = $1
			  AND email_verified_at IS NOT NULL
		`,
		1,
		registration.UserID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM email_verification_tokens
			WHERE user_id = $1
			  AND consumed_at IS NOT NULL
		`,
		1,
		registration.UserID,
	)

	_, err = service.VerifyEmail(
		ctx,
		delivery.Token,
	)
	if !errors.Is(
		err,
		auth.ErrInvalidEmailVerificationToken,
	) {
		t.Fatalf(
			"expected replay rejection, got %v",
			err,
		)
	}

	login, err := service.Login(
		ctx,
		auth.LoginInput{
			Email:    "owner@verified.test",
			Password: "correct horse battery staple",
			ClientIP: "127.0.0.1",
		},
	)
	if err != nil {
		t.Fatalf("login after verification: %v", err)
	}

	if login.UserID != registration.UserID {
		t.Fatal("login returned the wrong verified user")
	}
}

func TestEmailVerificationHTTPRoute(t *testing.T) {
	ctx := context.Background()
	sender := &recordingEmailVerificationSender{}

	service, _ :=
		newAuthenticationTestServiceWithEmailSender(
			t,
			ctx,
			sender,
		)

	_, err := service.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "HTTP Verification Company",
			TenantSlug:  "http-verification-company",
			Email:       "owner@http-verification.test",
			DisplayName: "HTTP Verification Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	if len(sender.deliveries) != 1 {
		t.Fatalf(
			"expected one verification delivery, got %d",
			len(sender.deliveries),
		)
	}

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication: service,
			SessionCookie:  httpapi.NewSessionCookie(true),
		},
	)

	response := performEmailVerificationRequest(
		t,
		router,
		sender.deliveries[0].Token,
	)

	if response.StatusCode != http.StatusNoContent {
		body := readResponseBody(t, response)
		t.Fatalf(
			"expected verification status %d, got %d: %s",
			http.StatusNoContent,
			response.StatusCode,
			body,
		)
	}

	_ = readResponseBody(t, response)

	replay := performEmailVerificationRequest(
		t,
		router,
		sender.deliveries[0].Token,
	)

	if replay.StatusCode != http.StatusBadRequest {
		body := readResponseBody(t, replay)
		t.Fatalf(
			"expected replay status %d, got %d: %s",
			http.StatusBadRequest,
			replay.StatusCode,
			body,
		)
	}

	replayBody := readResponseBody(t, replay)

	if !bytes.Contains(
		replayBody,
		[]byte("invalid or expired verification link"),
	) {
		t.Fatalf(
			"expected generic verification error, got %s",
			replayBody,
		)
	}
}

func performEmailVerificationRequest(
	t *testing.T,
	router http.Handler,
	token string,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(
		map[string]string{
			"token": token,
		},
	)
	if err != nil {
		t.Fatalf("encode verification request: %v", err)
	}

	return performRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/email/verify",
		bytes.NewReader(body),
		nil,
	)
}

func TestExpiredEmailVerificationTokenIsRejected(
	t *testing.T,
) {
	ctx := context.Background()
	sender := &recordingEmailVerificationSender{}

	service, pool :=
		newAuthenticationTestServiceWithEmailSender(
			t,
			ctx,
			sender,
		)

	registration, err := service.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Expired Company",
			TenantSlug:  "expired-company",
			Email:       "owner@expired.test",
			DisplayName: "Expired Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register user: %v", err)
	}

	if len(sender.deliveries) != 1 {
		t.Fatalf(
			"expected one verification delivery, got %d",
			len(sender.deliveries),
		)
	}

	_, err = pool.Exec(
		ctx,
		`
			UPDATE email_verification_tokens
			SET
				created_at = now() - interval '2 hours',
				expires_at = now() - interval '1 hour'
			WHERE user_id = $1
		`,
		registration.UserID,
	)
	if err != nil {
		t.Fatalf("expire verification token: %v", err)
	}

	_, err = service.VerifyEmail(
		ctx,
		sender.deliveries[0].Token,
	)
	if !errors.Is(
		err,
		auth.ErrInvalidEmailVerificationToken,
	) {
		t.Fatalf(
			"expected expired-token rejection, got %v",
			err,
		)
	}

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM users
			WHERE id = $1
			  AND email_verified_at IS NULL
		`,
		1,
		registration.UserID,
	)
}
