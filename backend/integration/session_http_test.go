package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

const testSessionCookieName = "gatehouse_session"

func TestHTTPSessionLifecycleAndFixationResistance(t *testing.T) {
	ctx := context.Background()
	authentication, pool := newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Session Company",
			TenantSlug:  "session-company",
			Email:       "owner@session.test",
			DisplayName: "Session Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register session user: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication: authentication,
			SessionCookie:  httpapi.NewSessionCookie(true),
		},
	)

	firstLogin := performLoginRequest(t, router, nil)
	if firstLogin.StatusCode != http.StatusOK {
		body := readResponseBody(t, firstLogin)
		t.Fatalf(
			"expected first login status %d, got %d: %s",
			http.StatusOK,
			firstLogin.StatusCode,
			body,
		)
	}

	firstBody := readResponseBody(t, firstLogin)
	firstCookie := requireSessionCookie(t, firstLogin)
	assertSecureSessionCookie(t, firstCookie)

	if bytes.Contains(firstBody, []byte(firstCookie.Value)) {
		t.Fatal("login response body exposed the raw session token")
	}

	assertStoredTokenHash(t, ctx, pool, firstCookie.Value)
	assertCurrentUser(t, router, firstCookie)

	secondLogin := performLoginRequest(t, router, firstCookie)
	if secondLogin.StatusCode != http.StatusOK {
		body := readResponseBody(t, secondLogin)
		t.Fatalf(
			"expected second login status %d, got %d: %s",
			http.StatusOK,
			secondLogin.StatusCode,
			body,
		)
	}

	_ = readResponseBody(t, secondLogin)
	secondCookie := requireSessionCookie(t, secondLogin)
	assertSecureSessionCookie(t, secondCookie)

	if firstCookie.Value == secondCookie.Value {
		t.Fatal("expected authentication to rotate the session token")
	}

	assertSessionRevoked(
		t,
		ctx,
		pool,
		firstCookie.Value,
		"rotated_after_authentication",
	)

	assertUnauthorizedCurrentUser(t, router, firstCookie)
	assertCurrentUser(t, router, secondCookie)

	logout := performRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/logout",
		nil,
		secondCookie,
	)

	if logout.StatusCode != http.StatusNoContent {
		body := readResponseBody(t, logout)
		t.Fatalf(
			"expected logout status %d, got %d: %s",
			http.StatusNoContent,
			logout.StatusCode,
			body,
		)
	}

	_ = readResponseBody(t, logout)

	clearedCookie := requireSessionCookie(t, logout)
	if clearedCookie.Value != "" {
		t.Fatal("expected logout to clear the cookie value")
	}

	if clearedCookie.MaxAge != -1 {
		t.Fatalf(
			"expected cleared cookie MaxAge -1, got %d",
			clearedCookie.MaxAge,
		)
	}

	assertSessionRevoked(
		t,
		ctx,
		pool,
		secondCookie.Value,
		"logout",
	)

	assertUnauthorizedCurrentUser(t, router, secondCookie)
}

func performLoginRequest(
	t *testing.T,
	router http.Handler,
	sessionCookie *http.Cookie,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"tenant_slug": "session-company",
		"email":       "owner@session.test",
		"password":    "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("encode login request: %v", err)
	}

	return performRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/login",
		bytes.NewReader(body),
		sessionCookie,
	)
}

func performRequest(
	t *testing.T,
	router http.Handler,
	method string,
	target string,
	body io.Reader,
	sessionCookie *http.Cookie,
) *http.Response {
	t.Helper()

	request := httptest.NewRequest(method, target, body)
	request.RemoteAddr = "192.0.2.10:54321"

	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	if sessionCookie != nil {
		request.AddCookie(sessionCookie)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	return recorder.Result()
}

func requireSessionCookie(
	t *testing.T,
	response *http.Response,
) *http.Cookie {
	t.Helper()

	for _, cookie := range response.Cookies() {
		if cookie.Name == testSessionCookieName {
			return cookie
		}
	}

	t.Fatal("response did not contain the session cookie")
	return nil
}

func assertSecureSessionCookie(
	t *testing.T,
	cookie *http.Cookie,
) {
	t.Helper()

	if cookie.Value == "" {
		t.Fatal("expected non-empty session cookie")
	}

	if !cookie.Secure {
		t.Fatal("expected Secure session cookie")
	}

	if !cookie.HttpOnly {
		t.Fatal("expected HttpOnly session cookie")
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf(
			"expected SameSite=Lax, got %v",
			cookie.SameSite,
		)
	}

	if cookie.Path != "/" {
		t.Fatalf("expected cookie path /, got %q", cookie.Path)
	}

	if cookie.Domain != "" {
		t.Fatalf(
			"expected host-only cookie, got domain %q",
			cookie.Domain,
		)
	}

	if cookie.MaxAge <= 0 {
		t.Fatalf(
			"expected positive cookie MaxAge, got %d",
			cookie.MaxAge,
		)
	}

	if cookie.Expires.IsZero() {
		t.Fatal("expected explicit cookie expiration")
	}
}

func assertStoredTokenHash(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	rawToken string,
) {
	t.Helper()

	expectedHash := hashTestSessionToken(t, rawToken)

	var storedHash []byte
	if err := pool.QueryRow(
		ctx,
		`
			SELECT token_hash
			FROM sessions
			WHERE token_hash = $1
		`,
		expectedHash,
	).Scan(&storedHash); err != nil {
		t.Fatalf("load stored session hash: %v", err)
	}

	if !bytes.Equal(storedHash, expectedHash) {
		t.Fatal("stored session hash did not match token digest")
	}

	if bytes.Equal(storedHash, []byte(rawToken)) {
		t.Fatal("database stored the raw session token")
	}
}

func assertSessionRevoked(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	rawToken string,
	expectedReason string,
) {
	t.Helper()

	tokenHash := hashTestSessionToken(t, rawToken)

	var revoked bool
	var reason string

	if err := pool.QueryRow(
		ctx,
		`
			SELECT
				revoked_at IS NOT NULL,
				COALESCE(revocation_reason, '')
			FROM sessions
			WHERE token_hash = $1
		`,
		tokenHash,
	).Scan(&revoked, &reason); err != nil {
		t.Fatalf("load revoked session: %v", err)
	}

	if !revoked {
		t.Fatal("expected session to be revoked")
	}

	if reason != expectedReason {
		t.Fatalf(
			"expected revocation reason %q, got %q",
			expectedReason,
			reason,
		)
	}
}

func assertCurrentUser(
	t *testing.T,
	router http.Handler,
	sessionCookie *http.Cookie,
) {
	t.Helper()

	response := performRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/auth/current-user",
		nil,
		sessionCookie,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf(
			"expected current-user status %d, got %d: %s",
			http.StatusOK,
			response.StatusCode,
			body,
		)
	}

	var body struct {
		Email               string `json:"email"`
		TenantSlug          string `json:"tenant_slug"`
		AuthenticationLevel string `json:"authentication_level"`
	}

	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode current-user response: %v", err)
	}

	if body.Email != "owner@session.test" {
		t.Fatalf("unexpected current-user email %q", body.Email)
	}

	if body.TenantSlug != "session-company" {
		t.Fatalf(
			"unexpected current-user tenant %q",
			body.TenantSlug,
		)
	}

	if body.AuthenticationLevel != "password" {
		t.Fatalf(
			"unexpected authentication level %q",
			body.AuthenticationLevel,
		)
	}
}

func assertUnauthorizedCurrentUser(
	t *testing.T,
	router http.Handler,
	sessionCookie *http.Cookie,
) {
	t.Helper()

	response := performRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/auth/current-user",
		nil,
		sessionCookie,
	)
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf(
			"expected revoked session status %d, got %d: %s",
			http.StatusUnauthorized,
			response.StatusCode,
			body,
		)
	}
}

func hashTestSessionToken(
	t *testing.T,
	rawToken string,
) []byte {
	t.Helper()

	tokenBytes, err := base64.RawURLEncoding.DecodeString(rawToken)
	if err != nil {
		t.Fatalf("decode session token: %v", err)
	}

	if len(tokenBytes) != 32 {
		t.Fatalf(
			"expected 32 token bytes, got %d",
			len(tokenBytes),
		)
	}

	digest := sha256.Sum256(tokenBytes)
	return digest[:]
}

func readResponseBody(
	t *testing.T,
	response *http.Response,
) []byte {
	t.Helper()
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return body
}
