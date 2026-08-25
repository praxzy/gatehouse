package oidc

import (
	"errors"
	"slices"
	"testing"
)

func TestProviderPublishesDiscoveryAndJWKS(
	t *testing.T,
) {
	config, err := NewProviderConfig(
		"https://identity.example.com",
	)
	if err != nil {
		t.Fatalf("create provider config: %v", err)
	}

	signingKey, err := ParseRSAPrivateKeyPEM(
		"provider-key-1",
		encodeTestPrivateKey(
			t,
			generateTestRSAKey(t, 2048),
		),
	)
	if err != nil {
		t.Fatalf("parse signing key: %v", err)
	}

	provider, err := NewProvider(
		config,
		signingKey,
	)
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}

	discovery := provider.DiscoveryDocument()

	if discovery.Issuer !=
		"https://identity.example.com" {
		t.Fatalf(
			"unexpected issuer %q",
			discovery.Issuer,
		)
	}

	if discovery.AuthorizationEndpoint !=
		"https://identity.example.com/oauth/authorize" {
		t.Fatalf(
			"unexpected authorization endpoint %q",
			discovery.AuthorizationEndpoint,
		)
	}

	if discovery.TokenEndpoint !=
		"https://identity.example.com/oauth/token" {
		t.Fatalf(
			"unexpected token endpoint %q",
			discovery.TokenEndpoint,
		)
	}

	if discovery.JWKSURI !=
		"https://identity.example.com/.well-known/jwks.json" {
		t.Fatalf(
			"unexpected JWKS URI %q",
			discovery.JWKSURI,
		)
	}

	if len(
		discovery.IDTokenSigningAlgorithmsSupported,
	) != 1 ||
		discovery.
			IDTokenSigningAlgorithmsSupported[0] !=
			"RS256" {
		t.Fatalf(
			"unexpected signing algorithms: %v",
			discovery.
				IDTokenSigningAlgorithmsSupported,
		)
	}

	for _, claim := range []string{
		"name",
		"email",
		"email_verified",
		"roles",
	} {
		if !slices.Contains(
			discovery.ClaimsSupported,
			claim,
		) {
			t.Fatalf(
				"discovery omitted claim %q: %v",
				claim,
				discovery.ClaimsSupported,
			)
		}
	}

	if len(
		discovery.CodeChallengeMethodsSupported,
	) != 1 ||
		discovery.
			CodeChallengeMethodsSupported[0] !=
			"S256" {
		t.Fatalf(
			"unexpected PKCE methods: %v",
			discovery.
				CodeChallengeMethodsSupported,
		)
	}

	keySet := provider.JSONWebKeySet()

	if len(keySet.Keys) != 1 {
		t.Fatalf(
			"expected one public key, got %d",
			len(keySet.Keys),
		)
	}

	publicKey := keySet.Keys[0]

	if publicKey.KeyID != "provider-key-1" ||
		publicKey.KeyType != "RSA" ||
		publicKey.Use != "sig" ||
		publicKey.Algorithm != "RS256" {
		t.Fatalf(
			"unexpected published JWK: %+v",
			publicKey,
		)
	}

	if publicKey.Modulus == "" ||
		publicKey.Exponent == "" {
		t.Fatal(
			"published JWK omitted RSA parameters",
		)
	}
}

func TestNewProviderRejectsInvalidConfiguration(
	t *testing.T,
) {
	signingKey, err := ParseRSAPrivateKeyPEM(
		"provider-key",
		encodeTestPrivateKey(
			t,
			generateTestRSAKey(t, 2048),
		),
	)
	if err != nil {
		t.Fatalf("parse signing key: %v", err)
	}

	t.Run(
		"zero issuer configuration",
		func(t *testing.T) {
			_, err := NewProvider(
				ProviderConfig{},
				signingKey,
			)

			if !errors.Is(
				err,
				ErrInvalidProviderConfiguration,
			) {
				t.Fatalf(
					"expected invalid provider configuration, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"modified derived endpoint",
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

			config.JWKSURI =
				"https://attacker.example/jwks.json"

			_, err = NewProvider(
				config,
				signingKey,
			)

			if !errors.Is(
				err,
				ErrInvalidProviderConfiguration,
			) {
				t.Fatalf(
					"expected modified endpoint rejection, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"missing signing key",
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

			_, err = NewProvider(config, nil)

			if !errors.Is(
				err,
				ErrInvalidProviderConfiguration,
			) {
				t.Fatalf(
					"expected missing key rejection, got %v",
					err,
				)
			}
		},
	)
}
