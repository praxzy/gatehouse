package oidcclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDiscoverValidatesProviderCapabilities(t *testing.T) {
	issuer := "https://id.example.test"
	httpClient := &http.Client{
		Transport: roundTripFunc(func(
			request *http.Request,
		) (*http.Response, error) {
			return jsonResponse(`{
                "issuer": "https://id.example.test",
                "authorization_endpoint": "https://id.example.test/oauth/authorize",
                "token_endpoint": "https://id.example.test/oauth/token",
                "jwks_uri": "https://id.example.test/.well-known/jwks.json",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "code_challenge_methods_supported": ["S256"]
            }`), nil
		}),
	}

	client, err := New(
		issuer,
		"client-id",
		"client-secret",
		"http://localhost:8090/oauth/callback",
		httpClient,
	)
	if err != nil {
		t.Fatalf("create OIDC client: %v", err)
	}

	provider, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("discover provider: %v", err)
	}

	if provider.Issuer != issuer ||
		provider.TokenEndpoint != issuer+"/oauth/token" {
		t.Fatalf("unexpected provider: %#v", provider)
	}
}

func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(
			request *http.Request,
		) (*http.Response, error) {
			return jsonResponse(`{
                "issuer": "https://attacker.example",
                "authorization_endpoint": "https://attacker.example/authorize",
                "token_endpoint": "https://attacker.example/token",
                "jwks_uri": "https://attacker.example/jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                "code_challenge_methods_supported": ["S256"]
            }`), nil
		}),
	}

	client, err := New(
		"https://id.example.test",
		"client-id",
		"client-secret",
		"http://localhost:8090/oauth/callback",
		httpClient,
	)
	if err != nil {
		t.Fatalf("create OIDC client: %v", err)
	}

	_, err = client.Discover(context.Background())
	if !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("expected ErrInvalidProvider, got %v", err)
	}
}

type roundTripFunc func(
	*http.Request,
) (*http.Response, error)

func (function roundTripFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return function(request)
}

func jsonResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}
