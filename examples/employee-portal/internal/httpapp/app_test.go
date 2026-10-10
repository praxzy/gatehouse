package httpapp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/praxzy/gatehouse/examples/employee-portal/internal/oidcclient"
	"github.com/praxzy/gatehouse/examples/employee-portal/internal/session"
)

type stubOIDCClient struct {
	flow      oidcclient.AuthorizationFlow
	identity  oidcclient.Identity
	exchanges int
}

func (stub *stubOIDCClient) Discover(
	ctx context.Context,
) (oidcclient.Provider, error) {
	return oidcclient.Provider{
		Issuer:                "https://id.example.test",
		AuthorizationEndpoint: "https://id.example.test/oauth/authorize",
		TokenEndpoint:         "https://id.example.test/oauth/token",
		JWKSURI:               "https://id.example.test/jwks",
	}, nil
}

func (stub *stubOIDCClient) AuthorizationURL(
	provider oidcclient.Provider,
	flow oidcclient.AuthorizationFlow,
) (string, error) {
	stub.flow = flow
	return provider.AuthorizationEndpoint +
		"?state=" + url.QueryEscape(flow.State), nil
}

func (stub *stubOIDCClient) ExchangeAndVerify(
	ctx context.Context,
	provider oidcclient.Provider,
	code string,
	verifier string,
	nonce string,
) (oidcclient.Identity, oidcclient.TokenResponse, error) {
	stub.exchanges++
	if code != "authorization-code" ||
		verifier != stub.flow.CodeVerifier ||
		nonce != stub.flow.Nonce {
		return oidcclient.Identity{},
			oidcclient.TokenResponse{},
			oidcclient.ErrInvalidIDToken
	}

	return stub.identity, oidcclient.TokenResponse{}, nil
}

func TestLoginCallbackCreatesLocalSession(t *testing.T) {
	now := time.Now().UTC()
	oidc := &stubOIDCClient{
		identity: oidcclient.Identity{
			Subject:   "user-123",
			Name:      "Alice Example",
			Email:     "alice@example.test",
			Roles:     []string{"Admin"},
			ExpiresAt: now.Add(5 * time.Minute),
		},
	}

	app := newTestApp(t, oidc)

	login := httptest.NewRecorder()
	app.Handler().ServeHTTP(
		login,
		httptest.NewRequest(http.MethodGet, "/login", nil),
	)
	if login.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d", login.Code)
	}

	loginResponse := login.Result()
	var flowCookie *http.Cookie
	for _, cookie := range loginResponse.Cookies() {
		if cookie.Name == authorizationCookieName {
			flowCookie = cookie
		}
	}
	if flowCookie == nil ||
		!flowCookie.HttpOnly ||
		flowCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("invalid authorization cookie: %#v", flowCookie)
	}

	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/callback?code=authorization-code&state="+
			url.QueryEscape(oidc.flow.State),
		nil,
	)
	callbackRequest.AddCookie(flowCookie)
	callback := httptest.NewRecorder()
	app.Handler().ServeHTTP(callback, callbackRequest)

	if callback.Code != http.StatusSeeOther ||
		callback.Header().Get("Location") != "/" ||
		oidc.exchanges != 1 {
		t.Fatalf(
			"unexpected callback result: status=%d location=%q exchanges=%d",
			callback.Code,
			callback.Header().Get("Location"),
			oidc.exchanges,
		)
	}

	var localCookie *http.Cookie
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			localCookie = cookie
		}
	}
	if localCookie == nil || !localCookie.HttpOnly {
		t.Fatalf("missing local session cookie: %#v", localCookie)
	}

	adminRequest := httptest.NewRequest(
		http.MethodGet,
		"/admin",
		nil,
	)
	adminRequest.AddCookie(localCookie)
	admin := httptest.NewRecorder()
	app.Handler().ServeHTTP(admin, adminRequest)
	if admin.Code != http.StatusOK ||
		!strings.Contains(admin.Body.String(), "Admin workspace") {
		t.Fatalf(
			"expected admin page, got %d: %s",
			admin.Code,
			admin.Body.String(),
		)
	}
	if admin.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"authenticated page may be cached: %q",
			admin.Header().Get("Cache-Control"),
		)
	}

	localSession, ok := app.sessions.GetSession(localCookie.Value)
	if !ok {
		t.Fatal("local session was unavailable before logout")
	}

	logoutRequest := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		strings.NewReader(url.Values{
			"csrf_token": {localSession.CSRFToken},
		}.Encode()),
	)
	logoutRequest.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	logoutRequest.AddCookie(localCookie)
	logout := httptest.NewRecorder()
	app.Handler().ServeHTTP(logout, logoutRequest)

	if logout.Code != http.StatusSeeOther ||
		logout.Header().Get("Location") != "/" {
		t.Fatalf(
			"unexpected logout response: status=%d location=%q",
			logout.Code,
			logout.Header().Get("Location"),
		)
	}
	if _, ok := app.sessions.GetSession(localCookie.Value); ok {
		t.Fatal("local session remained available after logout")
	}
}

func TestCallbackRejectsStateMismatchBeforeExchange(
	t *testing.T,
) {
	oidc := &stubOIDCClient{}
	app := newTestApp(t, oidc)

	login := httptest.NewRecorder()
	app.Handler().ServeHTTP(
		login,
		httptest.NewRequest(http.MethodGet, "/login", nil),
	)

	flowCookie := login.Result().Cookies()[0]
	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/callback?code=authorization-code&state=attacker",
		nil,
	)
	callbackRequest.AddCookie(flowCookie)
	callback := httptest.NewRecorder()
	app.Handler().ServeHTTP(callback, callbackRequest)

	if callback.Code != http.StatusBadRequest ||
		oidc.exchanges != 0 {
		t.Fatalf(
			"state mismatch reached exchange: status=%d exchanges=%d",
			callback.Code,
			oidc.exchanges,
		)
	}
}

func TestAdminRequiresSignedAdminRole(t *testing.T) {
	store := session.NewStore()
	app, err := New(&stubOIDCClient{}, store, false)
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	token, _, err := store.CreateSession(oidcclient.Identity{
		Subject:   "member-123",
		Name:      "Morgan Member",
		Email:     "morgan@example.test",
		Roles:     []string{"Member"},
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create member session: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/admin",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: token,
	})
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		body, _ := io.ReadAll(response.Result().Body)
		t.Fatalf(
			"expected 403, got %d: %s",
			response.Code,
			body,
		)
	}
}

func TestAdminRoleMatchingIsCaseInsensitive(t *testing.T) {
	for _, role := range []string{"Admin", "admin", "ADMIN", "AdMiN"} {
		t.Run(role, func(t *testing.T) {
			identity := oidcclient.Identity{Roles: []string{role}}
			if !hasRole(identity, "Admin") {
				t.Fatalf("expected role %q to match Admin", role)
			}
		})
	}

	identity := oidcclient.Identity{Roles: []string{"Administrator"}}
	if hasRole(identity, "Admin") {
		t.Fatal("Administrator must not match Admin")
	}
}

func TestLogoutRejectsMismatchedCSRFToken(t *testing.T) {
	store := session.NewStore()
	app, err := New(&stubOIDCClient{}, store, false)
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	token, _, err := store.CreateSession(oidcclient.Identity{
		Subject:   "user-123",
		Name:      "Alice",
		Email:     "alice@example.test",
		Roles:     []string{"Admin"},
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/logout",
		strings.NewReader("csrf_token=attacker-token"),
	)
	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: token,
	})
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected 403 for mismatched CSRF token, got %d",
			response.Code,
		)
	}
	if _, ok := store.GetSession(token); !ok {
		t.Fatal("mismatched CSRF token revoked the session")
	}
}

func newTestApp(
	t *testing.T,
	oidc OIDCClient,
) *App {
	t.Helper()

	app, err := New(oidc, session.NewStore(), false)
	if err != nil {
		t.Fatalf("create app: %v", err)
	}

	return app
}
