package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/federation"
)

type stubFederationManagementService struct {
	FederationManagementService

	saveResult  federation.ConnectionSummary
	saveErr     error
	saveInput   federation.SaveConnectionInput
	saveSession auth.SessionContext
	saveCalls   int
}

func (stub *stubFederationManagementService) SaveConnection(
	_ context.Context,
	session auth.SessionContext,
	input federation.SaveConnectionInput,
) (federation.ConnectionSummary, error) {
	stub.saveCalls++
	stub.saveSession = session
	stub.saveInput = input

	return stub.saveResult, stub.saveErr
}

func TestSaveFederationConnectionNeverReturnsClientSecret(
	t *testing.T,
) {
	now := time.Date(
		2026,
		time.September,
		23,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	management := &stubFederationManagementService{
		saveResult: federation.ConnectionSummary{
			ConnectionID: pgtype.UUID{
				Bytes: [16]byte{
					0x11, 0x11, 0x11, 0x11,
					0x11, 0x11,
					0x41, 0x11,
					0x81, 0x11,
					0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				},
				Valid: true,
			},
			DisplayName: "Workforce identity",
			Issuer:      "https://identity.example.com",
			ClientID:    "gatehouse-client",
			Status:      federation.ConnectionStatusEnabled,
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	}

	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/federation/connection",
		strings.NewReader(`{
			"display_name": "Workforce identity",
			"issuer": "https://identity.example.com",
			"client_id": "gatehouse-client",
			"client_secret": "super-secret-value"
		}`),
	)

	session := auth.SessionContext{
		TenantSlug: "acme",
		Permissions: []string{
			auth.PermissionFederationManage,
		},
	}

	request = request.WithContext(
		context.WithValue(
			request.Context(),
			sessionContextKey{},
			session,
		),
	)

	response := httptest.NewRecorder()

	federationManagementHandler{
		management: management,
	}.saveConnection(response, request)

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

	if management.saveInput.ClientSecret !=
		"super-secret-value" {
		t.Fatal(
			"expected client secret to reach management service",
		)
	}

	body := response.Body.String()

	for _, forbidden := range []string{
		"client_secret",
		"super-secret-value",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf(
				"response exposed forbidden value %q: %s",
				forbidden,
				body,
			)
		}
	}

	if !strings.Contains(
		body,
		`"client_id":"gatehouse-client"`,
	) {
		t.Fatalf(
			"response omitted safe connection data: %s",
			body,
		)
	}
}

func TestFederationManagementErrorsUseSafeStatusCodes(
	t *testing.T,
) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name: "forbidden",
			err: federation.
				ErrFederationManagementForbidden,
			expectedStatus: http.StatusForbidden,
		},
		{
			name: "invalid connection",
			err: federation.
				ErrInvalidFederationConnection,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "invalid identity mapping",
			err: federation.
				ErrInvalidIdentityMapping,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "connection not found",
			err: federation.
				ErrFederationConnectionNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "mapping target not found",
			err: federation.
				ErrIdentityMappingTargetNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name: "mapping already exists",
			err: federation.
				ErrIdentityMappingUnavailable,
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "unexpected internal error",
			err:            errors.New("database unavailable"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()

			writeFederationManagementError(
				response,
				test.err,
			)

			if response.Code != test.expectedStatus {
				t.Fatalf(
					"expected status %d, got %d",
					test.expectedStatus,
					response.Code,
				)
			}

			if strings.Contains(
				response.Body.String(),
				test.err.Error(),
			) {
				t.Fatalf(
					"response exposed internal error: %s",
					response.Body.String(),
				)
			}
		})
	}
}
