package federation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

func TestProviderHTTPClientRejectsUnsafeURLs(
	t *testing.T,
) {
	policy := ProviderNetworkPolicy{}

	tests := []struct {
		name   string
		rawURL string
	}{
		{
			name:   "plain HTTP",
			rawURL: "http://identity.example.com",
		},
		{
			name:   "localhost",
			rawURL: "https://localhost",
		},
		{
			name:   "localhost subdomain",
			rawURL: "https://login.localhost",
		},
		{
			name:   "IPv4 loopback",
			rawURL: "https://127.0.0.1",
		},
		{
			name:   "IPv6 loopback",
			rawURL: "https://[::1]",
		},
		{
			name:   "private IPv4",
			rawURL: "https://10.0.0.10",
		},
		{
			name:   "link-local metadata",
			rawURL: "https://169.254.169.254",
		},
		{
			name:   "carrier-grade NAT",
			rawURL: "https://100.64.0.1",
		},
		{
			name:   "URL credentials",
			rawURL: "https://user:password@identity.example.com",
		},
		{
			name:   "fragment",
			rawURL: "https://identity.example.com/issuer#fragment",
		},
		{
			name:   "relative URL",
			rawURL: "/issuer",
		},
		{
			name:   "unsupported scheme",
			rawURL: "file:///etc/passwd",
		},
		{
			name:   "surrounding whitespace",
			rawURL: " https://identity.example.com ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseProviderURL(
				test.rawURL,
				policy,
			)
			if err == nil {
				t.Fatal("expected unsafe URL rejection")
			}
		})
	}
}

func TestProviderHTTPClientAcceptsPublicHTTPSURL(
	t *testing.T,
) {
	parsed, err := parseProviderURL(
		"https://identity.example.com/tenant",
		ProviderNetworkPolicy{},
	)
	if err != nil {
		t.Fatalf("parse provider URL: %v", err)
	}

	if parsed.String() !=
		"https://identity.example.com/tenant" {
		t.Fatalf(
			"unexpected parsed URL: %s",
			parsed,
		)
	}
}

func TestProviderHTTPClientAllowsPrivateHTTPOnlyWhenConfigured(
	t *testing.T,
) {
	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.URL.Path != "/discovery" {
				http.NotFound(writer, request)
				return
			}

			writer.Header().Set(
				"Content-Type",
				"application/json",
			)
			_, _ = io.WriteString(
				writer,
				`{"issuer":"test"}`,
			)
		}),
	)
	defer server.Close()

	client := NewProviderHTTPClient(
		ProviderNetworkPolicy{
			AllowHTTP:             true,
			AllowPrivateAddresses: true,
		},
	)

	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL+"/discovery",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf(
			"unexpected status: %d",
			response.StatusCode,
		)
	}
}

func TestProviderHTTPClientDoesNotFollowRedirects(
	t *testing.T,
) {
	var targetCalls int

	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.URL.Path == "/redirect" {
				http.Redirect(
					writer,
					request,
					"/target",
					http.StatusFound,
				)
				return
			}

			if request.URL.Path == "/target" {
				targetCalls++
				writer.WriteHeader(http.StatusOK)
				return
			}

			http.NotFound(writer, request)
		}),
	)
	defer server.Close()

	client := NewProviderHTTPClient(
		ProviderNetworkPolicy{
			AllowHTTP:             true,
			AllowPrivateAddresses: true,
		},
	)

	request, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		server.URL+"/redirect",
		nil,
	)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("perform request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusFound {
		t.Fatalf(
			"unexpected redirect status: %d",
			response.StatusCode,
		)
	}

	if targetCalls != 0 {
		t.Fatalf(
			"redirect target was requested %d times",
			targetCalls,
		)
	}
}

func TestProviderHTTPClientRejectsInvalidRequests(
	t *testing.T,
) {
	client := NewProviderHTTPClient(
		ProviderNetworkPolicy{},
	)

	if _, err := client.Do(nil); !errors.Is(
		err,
		ErrInvalidProviderRequest,
	) {
		t.Fatalf(
			"expected invalid request error, got %v",
			err,
		)
	}

	request := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Scheme: "https",
			Host:   "127.0.0.1",
		},
	}

	if _, err := client.Do(request); !errors.Is(
		err,
		ErrUnsafeProviderAddress,
	) {
		t.Fatalf(
			"expected unsafe address error, got %v",
			err,
		)
	}
}

func TestUnsafeProviderAddressClassification(
	t *testing.T,
) {
	unsafeAddresses := []string{
		"0.0.0.0",
		"10.0.0.1",
		"100.64.0.1",
		"127.0.0.1",
		"169.254.169.254",
		"172.16.0.1",
		"192.168.1.1",
		"::",
		"::1",
		"fc00::1",
		"fe80::1",
	}

	for _, rawAddress := range unsafeAddresses {
		t.Run(
			strings.ReplaceAll(rawAddress, ":", "_"),
			func(t *testing.T) {
				parsed, err := netip.ParseAddr(
					rawAddress,
				)
				if err != nil {
					t.Fatalf(
						"parse test address: %v",
						err,
					)
				}

				if !unsafeProviderAddress(parsed) {
					t.Fatalf(
						"address %s was considered safe",
						rawAddress,
					)
				}
			},
		)
	}
}
