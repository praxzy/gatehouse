package oidc

import (
	"errors"
	"testing"
)

func TestNewProviderConfig(
	t *testing.T,
) {
	t.Run(
		"derives endpoints from HTTPS issuer",
		func(t *testing.T) {
			config, err := NewProviderConfig(
				"https://identity.example.com",
			)
			if err != nil {
				t.Fatalf(
					"create provider config: %v",
					err,
				)
			}

			if config.Issuer !=
				"https://identity.example.com" {
				t.Fatalf(
					"unexpected issuer %q",
					config.Issuer,
				)
			}

			if config.AuthorizationEndpoint !=
				"https://identity.example.com/oauth/authorize" {
				t.Fatalf(
					"unexpected authorization endpoint %q",
					config.AuthorizationEndpoint,
				)
			}

			if config.TokenEndpoint !=
				"https://identity.example.com/oauth/token" {
				t.Fatalf(
					"unexpected token endpoint %q",
					config.TokenEndpoint,
				)
			}

			if config.UserInfoEndpoint !=
				"https://identity.example.com/oidc/userinfo" {
				t.Fatalf(
					"unexpected userinfo endpoint %q",
					config.UserInfoEndpoint,
				)
			}

			if config.JWKSURI !=
				"https://identity.example.com/.well-known/jwks.json" {
				t.Fatalf(
					"unexpected JWKS URI %q",
					config.JWKSURI,
				)
			}
		},
	)

	t.Run(
		"allows localhost HTTP for development",
		func(t *testing.T) {
			config, err := NewProviderConfig(
				"http://localhost:8080",
			)
			if err != nil {
				t.Fatalf(
					"create local provider config: %v",
					err,
				)
			}

			if config.Issuer !=
				"http://localhost:8080" {
				t.Fatalf(
					"unexpected local issuer %q",
					config.Issuer,
				)
			}
		},
	)

	invalidIssuers := []string{
		"",
		" http://localhost:8080",
		"http://localhost:8080 ",
		"identity.example.com",
		"http://identity.example.com",
		"http://127.0.0.1:8080",
		"https://identity.example.com/",
		"https://identity.example.com/tenant",
		"https://identity.example.com?environment=test",
		"https://identity.example.com#fragment",
		"https://user@identity.example.com",
	}

	for _, issuer := range invalidIssuers {
		t.Run(
			"rejects "+issuer,
			func(t *testing.T) {
				_, err := NewProviderConfig(issuer)
				if !errors.Is(err, ErrInvalidIssuer) {
					t.Fatalf(
						"expected invalid issuer for %q, got %v",
						issuer,
						err,
					)
				}
			},
		)
	}
}
