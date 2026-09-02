package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

func TestHealthz(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}

	if contentType := response.Header().Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("expected application/json, got %q", contentType)
	}

	var body healthResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Status != "ok" {
		t.Fatalf("expected status ok, got %q", body.Status)
	}

	requestID := response.Header().Get(requestIDHeader)
	if _, err := uuid.Parse(requestID); err != nil {
		t.Fatalf("expected valid request ID, go %q", requestID)
	}
}

func TestErrorResponseIncludesRequestID(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/failure",
		nil,
	)
	response := httptest.NewRecorder()

	handler := attachRequestID(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writeError(
				writer,
				http.StatusBadRequest,
				"test failure",
			)
		}),
	)

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusBadRequest,
			response.Code,
		)
	}

	var body errorResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	headerRequestID := response.Header().Get(requestIDHeader)

	if body.RequestID == "" {
		t.Fatal("expected request_id in error response")
	}

	if body.RequestID != headerRequestID {
		t.Fatalf(
			"body request ID %q does not match header %q",
			body.RequestID,
			headerRequestID,
		)
	}
}

func TestRequestAuditDetailsUseDirectConnectionAddress(
	t *testing.T,
) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/test",
		nil,
	)
	request.RemoteAddr = "192.0.2.10:54321"
	request.Header.Set(
		"User-Agent",
		"Gatehouse test client",
	)
	request.Header.Set(
		"X-Forwarded-For",
		"203.0.113.50",
	)

	response := httptest.NewRecorder()

	handler := attachRequestID(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			details, ok := audit.RequestDetailsFromContext(
				request.Context(),
			)
			if !ok {
				t.Fatal("expected audit request details")
			}

			if details.RequestID == "" {
				t.Fatal("expected request ID")
			}

			if details.SourceIP == nil {
				t.Fatal("expected source IP")
			}

			if got := details.SourceIP.String(); got != "192.0.2.10" {
				t.Fatalf(
					"expected direct source IP, got %q",
					got,
				)
			}

			if details.UserAgent != "Gatehouse test client" {
				t.Fatalf(
					"unexpected user agent %q",
					details.UserAgent,
				)
			}

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
