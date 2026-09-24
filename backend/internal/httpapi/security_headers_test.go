package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeadersAreApplied(
	t *testing.T,
) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/healthz",
		nil,
	)
	response := httptest.NewRecorder()

	securityHeaders(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(http.StatusOK)
		}),
	).ServeHTTP(response, request)

	expected := map[string]string{
		"Content-Security-Policy":           "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"Referrer-Policy":                   "no-referrer",
		"Permissions-Policy":                "camera=(), geolocation=(), microphone=()",
		"Cross-Origin-Opener-Policy":        "same-origin",
		"X-Permitted-Cross-Domain-Policies": "none",
	}

	for name, value := range expected {
		if response.Header().Get(name) != value {
			t.Fatalf(
				"expected %s %q, got %q",
				name,
				value,
				response.Header().Get(name),
			)
		}
	}
}
