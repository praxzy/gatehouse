package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/federation"
)

type csrfRouterAuthentication struct {
	AuthenticationService

	session auth.SessionContext
}

func (stub *csrfRouterAuthentication) ResolveSession(
	_ context.Context,
	_ string,
) (auth.SessionContext, error) {
	return stub.session, nil
}

type csrfRouterFederationManagement struct {
	FederationManagementService

	saveCalls int
}

func (stub *csrfRouterFederationManagement) SaveConnection(
	_ context.Context,
	_ auth.SessionContext,
	input federation.SaveConnectionInput,
) (federation.ConnectionSummary, error) {
	stub.saveCalls++

	now := time.Now().UTC()

	return federation.ConnectionSummary{
		DisplayName: input.DisplayName,
		Issuer:      input.Issuer,
		ClientID:    input.ClientID,
		Status:      federation.ConnectionStatusEnabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func newCSRFRouterFixture(
	t *testing.T,
) (http.Handler, string, string, *csrfRouterFederationManagement) {
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

	sessionToken := "router-test-session"

	csrfToken, err :=
		protector.Token(sessionToken)
	if err != nil {
		t.Fatalf(
			"create CSRF token: %v",
			err,
		)
	}

	authentication := &csrfRouterAuthentication{
		session: auth.SessionContext{
			AuthenticationLevel: "mfa",
			Permissions: []string{
				auth.PermissionFederationManage,
			},
		},
	}

	management :=
		&csrfRouterFederationManagement{}

	router := NewRouter(Dependencies{
		Authentication:       authentication,
		FederationManagement: management,
		SessionCookie:        NewSessionCookie(false),
		CSRF:                 protector,
	})

	return router,
		sessionToken,
		csrfToken,
		management
}

func TestRouterRejectsAdminMutationWithoutCSRFToken(
	t *testing.T,
) {
	router, sessionToken, _, management :=
		newCSRFRouterFixture(t)

	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/federation/connection",
		strings.NewReader(`{
			"display_name": "Workforce",
			"issuer": "https://identity.example.com",
			"client_id": "gatehouse",
			"client_secret": "secret"
		}`),
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
		"Content-Type",
		"application/json",
	)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusForbidden,
			response.Code,
			response.Body.String(),
		)
	}

	if management.saveCalls != 0 {
		t.Fatal(
			"mutation reached service without CSRF token",
		)
	}
}

func TestRouterAllowsAdminMutationWithValidCSRFToken(
	t *testing.T,
) {
	router, sessionToken, csrfToken, management :=
		newCSRFRouterFixture(t)

	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/federation/connection",
		strings.NewReader(`{
			"display_name": "Workforce",
			"issuer": "https://identity.example.com",
			"client_id": "gatehouse",
			"client_secret": "secret"
		}`),
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
	request.Header.Set(
		"Content-Type",
		"application/json",
	)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusOK,
			response.Code,
			response.Body.String(),
		)
	}

	if management.saveCalls != 1 {
		t.Fatalf(
			"expected one save call, got %d",
			management.saveCalls,
		)
	}
}

func TestRouterIssuesCSRFTokenForAuthenticatedSession(
	t *testing.T,
) {
	router, sessionToken, csrfToken, _ :=
		newCSRFRouterFixture(t)

	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/csrf",
		nil,
	)
	request.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})

	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d: %s",
			http.StatusOK,
			response.Code,
			response.Body.String(),
		)
	}

	if !strings.Contains(
		response.Body.String(),
		csrfToken,
	) {
		t.Fatalf(
			"response omitted CSRF token: %s",
			response.Body.String(),
		)
	}

	if response.Header().Get("Cache-Control") !=
		"no-store" {
		t.Fatalf(
			"unexpected cache control %q",
			response.Header().Get("Cache-Control"),
		)
	}
}
