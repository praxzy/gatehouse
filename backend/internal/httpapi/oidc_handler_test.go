package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

type staticOIDCMetadata struct {
	discovery oidc.DiscoveryDocument
	keySet    oidc.JSONWebKeySet
}

func (
	metadata staticOIDCMetadata,
) DiscoveryDocument() oidc.DiscoveryDocument {
	return metadata.discovery
}

func (
	metadata staticOIDCMetadata,
) JSONWebKeySet() oidc.JSONWebKeySet {
	return metadata.keySet
}

func TestOIDCDiscoveryIsPublicAndCacheable(
	t *testing.T,
) {
	metadata := staticOIDCMetadata{
		discovery: oidc.DiscoveryDocument{
			Issuer:                "https://identity.example.com",
			AuthorizationEndpoint: "https://identity.example.com/oauth/authorize",
			TokenEndpoint:         "https://identity.example.com/oauth/token",
			UserInfoEndpoint:      "https://identity.example.com/oidc/userinfo",
			JWKSURI:               "https://identity.example.com/.well-known/jwks.json",
			ResponseTypesSupported: []string{
				"code",
			},
			SubjectTypesSupported: []string{
				"public",
			},
			IDTokenSigningAlgorithmsSupported: []string{
				"RS256",
			},
		},
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/openid-configuration",
		nil,
	)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		OIDCMetadata: metadata,
	}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			response.Code,
		)
	}

	if response.Header().Get("Cache-Control") !=
		discoveryCacheControl {
		t.Fatalf(
			"unexpected cache control %q",
			response.Header().Get("Cache-Control"),
		)
	}

	if response.Header().Get("Content-Type") !=
		"application/json" {
		t.Fatalf(
			"unexpected content type %q",
			response.Header().Get("Content-Type"),
		)
	}

	var document oidc.DiscoveryDocument
	if err := json.NewDecoder(
		response.Body,
	).Decode(&document); err != nil {
		t.Fatalf(
			"decode discovery document: %v",
			err,
		)
	}

	if document.Issuer !=
		"https://identity.example.com" {
		t.Fatalf(
			"unexpected issuer %q",
			document.Issuer,
		)
	}

	if document.JWKSURI !=
		"https://identity.example.com/.well-known/jwks.json" {
		t.Fatalf(
			"unexpected JWKS URI %q",
			document.JWKSURI,
		)
	}
}

func TestOIDCJWKSIsPublicAndContainsOnlyPublicMaterial(
	t *testing.T,
) {
	metadata := staticOIDCMetadata{
		keySet: oidc.JSONWebKeySet{
			Keys: []oidc.JWK{
				{
					KeyType:   "RSA",
					Use:       "sig",
					KeyID:     "test-key-1",
					Algorithm: "RS256",
					Modulus:   "test-modulus",
					Exponent:  "AQAB",
				},
			},
		},
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		OIDCMetadata: metadata,
	}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			response.Code,
		)
	}

	if response.Header().Get("Cache-Control") !=
		jwksCacheControl {
		t.Fatalf(
			"unexpected cache control %q",
			response.Header().Get("Cache-Control"),
		)
	}

	body := response.Body.String()

	for _, privateField := range []string{
		`"d"`,
		`"p"`,
		`"q"`,
		`"dp"`,
		`"dq"`,
		`"qi"`,
	} {
		if strings.Contains(body, privateField) {
			t.Fatalf(
				"JWKS exposed private field %s: %s",
				privateField,
				body,
			)
		}
	}

	var keySet oidc.JSONWebKeySet
	if err := json.Unmarshal(
		[]byte(body),
		&keySet,
	); err != nil {
		t.Fatalf("decode JWKS: %v", err)
	}

	if len(keySet.Keys) != 1 {
		t.Fatalf(
			"expected one JWK, got %d",
			len(keySet.Keys),
		)
	}

	if keySet.Keys[0].KeyID != "test-key-1" {
		t.Fatalf(
			"unexpected key ID %q",
			keySet.Keys[0].KeyID,
		)
	}
}
