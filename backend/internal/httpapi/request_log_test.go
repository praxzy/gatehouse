package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRequestLoggerEmitsSafeCorrelatedIdentity(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	router := chi.NewRouter()
	router.Use(attachRequestID)
	router.Use(requestLogger(logger))
	router.Get(
		"/applications/{applicationID}",
		func(writer http.ResponseWriter, request *http.Request) {
			setRequestLogIdentity(
				request.Context(),
				"tenant-123",
				"user-456",
				"application-789",
			)

			writer.WriteHeader(http.StatusNoContent)
		},
	)

	request := httptest.NewRequest(
		http.MethodGet,
		"/applications/application-789?code=must-not-be-logged",
		nil,
	)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode request log: %v", err)
	}

	if entry["request_id"] != response.Header().Get(requestIDHeader) {
		t.Fatalf(
			"log request ID %#v does not match response",
			entry["request_id"],
		)
	}

	assertLogValue(t, entry, "method", http.MethodGet)
	assertLogValue(
		t,
		entry,
		"route",
		"/applications/{applicationID}",
	)
	assertLogValue(t, entry, "status", float64(http.StatusNoContent))
	assertLogValue(t, entry, "tenant_id", "tenant-123")
	assertLogValue(t, entry, "user_id", "user-456")
	assertLogValue(t, entry, "application_id", "application-789")

	if bytes.Contains(output.Bytes(), []byte("must-not-be-logged")) {
		t.Fatal("request query was written to the structured log")
	}
}

func TestRequestLoggerSkipsSuccessfulHealthProbe(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	router := chi.NewRouter()
	router.Use(attachRequestID)
	router.Use(requestLogger(logger))
	router.Get("/healthz", healthz)

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if output.Len() != 0 {
		t.Fatalf("successful health probe was logged: %s", output.String())
	}
}

func assertLogValue(
	t *testing.T,
	entry map[string]any,
	key string,
	want any,
) {
	t.Helper()

	if got := entry[key]; got != want {
		t.Fatalf("unexpected %s: got %#v, want %#v", key, got, want)
	}
}
