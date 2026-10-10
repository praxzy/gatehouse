package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientAddressTrustBoundary(t *testing.T) {
	t.Run("direct deployment ignores forwarded address", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "192.0.2.10:54321"
		request.Header.Set("X-Forwarded-For", "203.0.113.50")

		address, err := requestClientAddress(request, false)
		if err != nil {
			t.Fatalf("resolve direct client address: %v", err)
		}
		if got := address.String(); got != "192.0.2.10" {
			t.Fatalf("expected direct address, got %q", got)
		}
	})

	t.Run("trusted proxy uses rightmost appended address", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "10.0.1.25:8080"
		request.Header.Set(
			"X-Forwarded-For",
			"198.51.100.99, 203.0.113.50",
		)

		address, err := requestClientAddress(request, true)
		if err != nil {
			t.Fatalf("resolve proxied client address: %v", err)
		}
		if got := address.String(); got != "203.0.113.50" {
			t.Fatalf("expected ALB-appended address, got %q", got)
		}
	})

	t.Run("trusted proxy accepts bracketed IPv6 with port", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "10.0.1.25:8080"
		request.Header.Set(
			"X-Forwarded-For",
			"[2001:db8::1234]:443",
		)

		address, err := requestClientAddress(request, true)
		if err != nil {
			t.Fatalf("resolve proxied IPv6 address: %v", err)
		}
		if got := address.String(); got != "2001:db8::1234" {
			t.Fatalf("unexpected IPv6 address %q", got)
		}
	})

	t.Run("malformed appended address fails closed", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.RemoteAddr = "10.0.1.25:8080"
		request.Header.Set(
			"X-Forwarded-For",
			"198.51.100.99, not-an-address",
		)

		if _, err := requestClientAddress(request, true); err == nil {
			t.Fatal("expected malformed proxy address rejection")
		}
	})
}
