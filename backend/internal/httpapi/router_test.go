package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
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
