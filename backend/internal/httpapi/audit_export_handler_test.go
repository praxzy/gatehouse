package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auditexport"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type exportAuthStub struct {
	AuthenticationService
	session auth.SessionContext
}

func (stub exportAuthStub) ResolveSession(
	_ context.Context,
	_ string,
) (auth.SessionContext, error) {
	return stub.session, nil
}

type exportServiceStub struct {
	calls  int
	input  auditexport.CreateInput
	result auditexport.CreateResult
}

func (stub *exportServiceStub) Create(
	_ context.Context,
	_ auth.SessionContext,
	input auditexport.CreateInput,
) (auditexport.CreateResult, error) {
	stub.calls++
	stub.input = input
	return stub.result, nil
}

func performExportRequest(
	session auth.SessionContext,
	exports AuditExportService,
	body string,
	withCookie bool,
) *httptest.ResponseRecorder {
	router := NewRouter(Dependencies{
		Authentication: exportAuthStub{session: session},
		AuditExports:   exports,
		SessionCookie:  NewSessionCookie(false),
	})
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/audit-exports",
		strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	if withCookie {
		request.AddCookie(&http.Cookie{
			Name:  sessionCookieName,
			Value: "test-session",
		})
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestAuditExportRoute(t *testing.T) {
	session := auth.SessionContext{
		AuthenticationLevel: "mfa",
		MFARequired:         true,
		Permissions:         []string{auth.PermissionAuditExport},
	}
	jobID := pgtype.UUID{
		Bytes: [16]byte{1},
		Valid: true,
	}
	exports := &exportServiceStub{
		result: auditexport.CreateResult{
			Job: store.ExportJob{
				ID:     jobID,
				Status: "queued",
				Format: "csv",
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
					Valid: true,
				},
			},
			// A deferred SQS send must still receive 202.
			Enqueued: false,
		},
	}

	t.Run("accepted", func(t *testing.T) {
		response := performExportRequest(
			session,
			exports,
			`{"format":"csv","event_type":"auth.login","outcome":"failure"}`,
			true,
		)
		if response.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d: %s", response.Code, response.Body)
		}
		if exports.calls != 1 ||
			exports.input.Format != "csv" ||
			exports.input.EventType != "auth.login" ||
			exports.input.Outcome != "failure" {
			t.Fatalf("unexpected service call: %+v", exports.input)
		}

		var body createAuditExportResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.JobID != formatUUID(jobID) ||
			body.Status != "queued" ||
			body.Format != "csv" {
			t.Fatalf("unexpected response: %+v", body)
		}
	})

	t.Run("no session", func(t *testing.T) {
		response := performExportRequest(session, exports, `{}`, false)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", response.Code)
		}
	})

	t.Run("MFA incomplete", func(t *testing.T) {
		passwordSession := session
		passwordSession.AuthenticationLevel = "password"
		response := performExportRequest(
			passwordSession, exports, `{}`, true,
		)
		if response.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", response.Code)
		}
	})

	t.Run("permission denied", func(t *testing.T) {
		memberSession := session
		memberSession.Permissions = nil
		response := performExportRequest(
			memberSession, exports, `{}`, true,
		)
		if response.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", response.Code)
		}
	})

	t.Run("exports disabled", func(t *testing.T) {
		response := performExportRequest(
			session, nil, `{"format":"csv"}`, true,
		)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", response.Code)
		}
	})

	t.Run("invalid filter", func(t *testing.T) {
		callsBefore := exports.calls
		response := performExportRequest(
			session,
			exports,
			`{"format":"csv","actor_user_id":"not-a-uuid"}`,
			true,
		)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", response.Code)
		}
		if exports.calls != callsBefore {
			t.Fatal("invalid filter reached the service")
		}
	})
}
