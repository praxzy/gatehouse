package observability_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/observability"
)

func TestJSONLoggerEmitsStructuredAttributes(t *testing.T) {
	var output bytes.Buffer

	logger := observability.NewJSONLogger(&output)
	logger.Info(
		"request completed",
		"request_id", "request-123",
		"status", 204,
	)

	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatalf("decode structured log: %v", err)
	}

	if entry["msg"] != "request completed" {
		t.Fatalf("unexpected message %#v", entry["msg"])
	}

	if entry["request_id"] != "request-123" {
		t.Fatalf(
			"unexpected request ID %#v",
			entry["request_id"],
		)
	}

	if entry["status"] != float64(204) {
		t.Fatalf("unexpected status %#v", entry["status"])
	}
}
