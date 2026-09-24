package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestCSRFProtector(
	t *testing.T,
) (*CSRFProtector, string, string) {
	t.Helper()

	protector, err := NewCSRFProtector(
		bytes.Repeat([]byte{0x42}, 32),
		[]string{
			"http://localhost:5173",
		},
	)
	if err != nil {
		t.Fatalf(
			"create CSRF protector: %v",
			err,
		)
	}

	sessionToken := "test-session-token"

	csrfToken, err :=
		protector.Token(sessionToken)
	if err != nil {
		t.Fatalf(
			"create CSRF token: %v",
			err,
		)
	}

	return protector, sessionToken, csrfToken
}

func TestCSRFProtectorAllowsValidMutation(
	t *testing.T,
) {
	protector, sessionToken, csrfToken :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/members",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	request.Header.Set(
		"Origin",
		"http://localhost:5173",
	)
	request.Header.Set(
		csrfHeaderName,
		csrfToken,
	)

	response := httptest.NewRecorder()

	handler := protector.Protect(
		NewSessionCookie(false),
	)(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(
				http.StatusNoContent,
			)
		}),
	)

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}
}

func TestCSRFProtectorRejectsMissingToken(
	t *testing.T,
) {
	protector, sessionToken, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/members",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	request.Header.Set(
		"Origin",
		"http://localhost:5173",
	)

	response := httptest.NewRecorder()

	protector.Protect(
		NewSessionCookie(false),
	)(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			t.Fatal(
				"request without CSRF token reached handler",
			)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusForbidden,
			response.Code,
		)
	}
}

func TestCSRFProtectorRejectsBadOrigin(
	t *testing.T,
) {
	protector, sessionToken, csrfToken :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/members",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	request.Header.Set(
		"Origin",
		"https://attacker.example",
	)
	request.Header.Set(
		csrfHeaderName,
		csrfToken,
	)

	response := httptest.NewRecorder()

	protector.Protect(
		NewSessionCookie(false),
	)(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			t.Fatal(
				"request from bad origin reached handler",
			)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusForbidden,
			response.Code,
		)
	}
}

func TestCSRFProtectorAllowsRefererFallback(
	t *testing.T,
) {
	protector, sessionToken, csrfToken :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/members/test",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	request.Header.Set(
		"Referer",
		"http://localhost:5173/members?tab=active",
	)
	request.Header.Set(
		csrfHeaderName,
		csrfToken,
	)

	response := httptest.NewRecorder()

	protector.Protect(
		NewSessionCookie(false),
	)(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(
				http.StatusNoContent,
			)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}
}

func TestCSRFProtectorAllowsSafeRequest(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/members",
		nil,
	)
	response := httptest.NewRecorder()

	protector.Protect(
		NewSessionCookie(false),
	)(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(
				http.StatusNoContent,
			)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusNoContent,
			response.Code,
		)
	}
}

func TestCSRFTokenIsBoundToSession(
	t *testing.T,
) {
	protector, _, first :=
		newTestCSRFProtector(t)

	second, err := protector.Token(
		"different-session-token",
	)
	if err != nil {
		t.Fatalf(
			"create second token: %v",
			err,
		)
	}

	if first == second {
		t.Fatal(
			"expected different sessions to have different CSRF tokens",
		)
	}
}

func TestCSRFProtectorRejectsPublicMutationFromBadOrigin(
	t *testing.T,
) {
	protector, _, _ :=
		newTestCSRFProtector(t)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/login",
		nil,
	)
	request.Header.Set(
		"Origin",
		"https://attacker.example",
	)

	response := httptest.NewRecorder()

	protector.ProtectOrigin(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			t.Fatal(
				"bad-origin request reached handler",
			)
		}),
	).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusForbidden,
			response.Code,
		)
	}
}
