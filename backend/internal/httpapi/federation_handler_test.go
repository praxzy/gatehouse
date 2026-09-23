package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/federation"
)

type fakeFederationStarter struct {
	result federation.BeginAuthorizationResult
	err    error
	input  federation.BeginAuthorizationInput
	calls  int
}

func (fake *fakeFederationStarter) Begin(
	_ context.Context,
	input federation.BeginAuthorizationInput,
) (federation.BeginAuthorizationResult, error) {
	fake.calls++
	fake.input = input

	return fake.result, fake.err
}

type fakeFederationCompleter struct {
	result federation.CompleteAuthorizationResult
	err    error
	input  federation.CompleteAuthorizationInput
	calls  int
}

func (fake *fakeFederationCompleter) Complete(
	_ context.Context,
	input federation.CompleteAuthorizationInput,
) (federation.CompleteAuthorizationResult, error) {
	fake.calls++
	fake.input = input

	return fake.result, fake.err
}

func TestFederationStartRedirectsToUpstreamProvider(
	t *testing.T,
) {
	starter := &fakeFederationStarter{
		result: federation.BeginAuthorizationResult{
			AuthorizationURL: "https://identity.example.com/authorize?state=test",
		},
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/federation/acme/start?return_to=%2Fdashboard",
		nil,
	)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		FederationAuthorization: starter,
	}).ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusFound,
			response.Code,
		)
	}

	if response.Header().Get("Location") !=
		starter.result.AuthorizationURL {
		t.Fatalf(
			"unexpected redirect %q",
			response.Header().Get("Location"),
		)
	}

	if response.Header().Get("Cache-Control") !=
		"no-store" {
		t.Fatalf(
			"unexpected cache control %q",
			response.Header().Get("Cache-Control"),
		)
	}

	if starter.calls != 1 ||
		starter.input.TenantSlug != "acme" ||
		starter.input.ReturnPath != "/dashboard" {
		t.Fatalf(
			"unexpected begin input: %+v",
			starter.input,
		)
	}
}

func TestFederationCallbackCreatesSessionAndRedirects(
	t *testing.T,
) {
	expiresAt := time.Now().
		Add(time.Hour).
		UTC()

	completer := &fakeFederationCompleter{
		result: federation.CompleteAuthorizationResult{
			Session: auth.SessionGrant{
				Token:     "new-session-token",
				ExpiresAt: expiresAt,
			},
			ReturnPath: "/dashboard",
		},
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/federation/callback?state=test-state&code=test-code",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "previous-session-token",
	})

	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		FederationCallback: completer,
		SessionCookie:      NewSessionCookie(false),
	}).ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusFound,
			response.Code,
		)
	}

	if response.Header().Get("Location") !=
		"/dashboard" {
		t.Fatalf(
			"unexpected redirect %q",
			response.Header().Get("Location"),
		)
	}

	if completer.calls != 1 ||
		completer.input.State != "test-state" ||
		completer.input.Code != "test-code" ||
		completer.input.ProviderError != "" ||
		completer.input.PreviousSession !=
			"previous-session-token" {
		t.Fatalf(
			"unexpected callback input: %+v",
			completer.input,
		)
	}

	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf(
			"expected one session cookie, got %d",
			len(cookies),
		)
	}

	cookie := cookies[0]
	if cookie.Name != sessionCookieName ||
		cookie.Value != "new-session-token" ||
		!cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf(
			"unexpected session cookie: %+v",
			cookie,
		)
	}
}

func TestFederationCallbackRejectsDuplicateProtocolParameters(
	t *testing.T,
) {
	completer := &fakeFederationCompleter{}

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/federation/callback?state=test-state&code=first&code=second",
		nil,
	)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		FederationCallback: completer,
	}).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusBadRequest,
			response.Code,
		)
	}

	if completer.calls != 0 {
		t.Fatal(
			"malformed callback reached federation service",
		)
	}
}

func TestFederationCallbackMapsSafeErrors(
	t *testing.T,
) {
	testCases := []struct {
		name   string
		err    error
		status int
	}{
		{
			name: "invalid callback",
			err: federation.
				ErrInvalidAuthorizationCallback,
			status: http.StatusBadRequest,
		},
		{
			name: "provider denied",
			err: federation.
				ErrUpstreamAuthorizationDenied,
			status: http.StatusForbidden,
		},
		{
			name: "identity not mapped",
			err: federation.
				ErrUpstreamIdentityNotMapped,
			status: http.StatusForbidden,
		},
		{
			name: "provider unavailable",
			err: federation.
				ErrFederationUnavailable,
			status: http.StatusBadGateway,
		},
		{
			name:   "internal failure",
			err:    errors.New("database unavailable"),
			status: http.StatusInternalServerError,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			completer :=
				&fakeFederationCompleter{
					err: test.err,
				}

			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/auth/federation/callback?state=test-state&code=test-code",
				nil,
			)
			response := httptest.NewRecorder()

			NewRouter(Dependencies{
				FederationCallback: completer,
			}).ServeHTTP(response, request)

			if response.Code != test.status {
				t.Fatalf(
					"expected status %d, got %d",
					test.status,
					response.Code,
				)
			}

			if completer.calls != 1 {
				t.Fatalf(
					"expected one callback call, got %d",
					completer.calls,
				)
			}
		})
	}
}
