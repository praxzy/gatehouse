package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

func TestRequirePermissionRejectsMissingPermission(
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
			Permissions: []string{
				auth.PermissionMemberRead,
			},
		},
	)

	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	nextCalled := false

	handler := requirePermission(
		auth.PermissionMemberManage,
	)(
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
		t.Fatal("request without permission reached handler")
	}
}

func TestRequirePermissionAllowsMatchingPermission(
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
			Permissions: []string{
				auth.PermissionMemberManage,
			},
		},
	)

	request = request.WithContext(ctx)
	response := httptest.NewRecorder()

	handler := requirePermission(
		auth.PermissionMemberManage,
	)(
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
