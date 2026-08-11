package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

func TestRequireFullyAuthenticatedRejectsPasswordOnlySession(
	t *testing.T,
) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/protected",
		nil,
	)

	ctx := context.WithValue(
		request.Context(),
		sessionContextKey{},
		auth.SessionContext{
			AuthenticationLevel: "password",
			MFARequired:         true,
			MFAEnrolled:         true,
		},
	)

	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	nextCalled := false

	handler := requireFullyAuthenticated(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			nextCalled = true
			writer.WriteHeader(http.StatusNoContent)
		}),
	)

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusForbidden,
			response.Code,
		)
	}

	if nextCalled {
		t.Fatal("password-level session reached protected handler")
	}
}

func TestRequireFullyAuthenticatedAllowsMFASession(
	t *testing.T,
) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/protected",
		nil,
	)

	ctx := context.WithValue(
		request.Context(),
		sessionContextKey{},
		auth.SessionContext{
			AuthenticationLevel: "mfa",
			MFARequired:         true,
			MFAEnrolled:         true,
		},
	)

	request = request.WithContext(ctx)
	response := httptest.NewRecorder()

	handler := requireFullyAuthenticated(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(http.StatusNoContent)
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
