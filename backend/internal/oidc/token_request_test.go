package oidc

import (
	"errors"
	"net/url"
	"testing"
)

const (
	testTokenCode = "ghac_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	testTokenVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	testTokenChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	testTokenClientID = "ghc_0123456789abcdefghijklmnopqrstuv"
)

func TestParseTokenRequest(
	t *testing.T,
) {
	values := validTokenRequestValues()

	request, err := ParseTokenRequest(values)
	if err != nil {
		t.Fatalf("parse token request: %v", err)
	}

	if request.GrantType != "authorization_code" ||
		request.Code != testTokenCode ||
		request.RedirectURI !=
			"https://portal.example.test/oauth/callback" ||
		request.CodeVerifier != testTokenVerifier ||
		request.ClientID != testTokenClientID {
		t.Fatalf(
			"unexpected token request: %+v",
			request,
		)
	}
}

func TestParseTokenRequestRejectsInvalidValues(
	t *testing.T,
) {
	tests := []struct {
		name     string
		mutate   func(url.Values)
		expected error
	}{
		{
			name: "unsupported grant",
			mutate: func(values url.Values) {
				values.Set(
					"grant_type",
					"client_credentials",
				)
			},
			expected: ErrUnsupportedTokenGrantType,
		},
		{
			name: "missing code",
			mutate: func(values url.Values) {
				values.Del("code")
			},
			expected: ErrInvalidTokenRequest,
		},
		{
			name: "malformed code",
			mutate: func(values url.Values) {
				values.Set("code", "not-a-code")
			},
			expected: ErrInvalidTokenRequest,
		},
		{
			name: "missing redirect URI",
			mutate: func(values url.Values) {
				values.Del("redirect_uri")
			},
			expected: ErrInvalidTokenRequest,
		},
		{
			name: "short verifier",
			mutate: func(values url.Values) {
				values.Set("code_verifier", "too-short")
			},
			expected: ErrInvalidPKCEVerifier,
		},
		{
			name: "invalid verifier character",
			mutate: func(values url.Values) {
				values.Set(
					"code_verifier",
					testTokenVerifier+"!",
				)
			},
			expected: ErrInvalidPKCEVerifier,
		},
		{
			name: "malformed client ID",
			mutate: func(values url.Values) {
				values.Set("client_id", "client")
			},
			expected: ErrInvalidTokenRequest,
		},
		{
			name: "client secret in body",
			mutate: func(values url.Values) {
				values.Set(
					"client_secret",
					"unsupported",
				)
			},
			expected: ErrInvalidTokenRequest,
		},
		{
			name: "duplicate code",
			mutate: func(values url.Values) {
				values["code"] = append(
					values["code"],
					testTokenCode,
				)
			},
			expected: ErrInvalidTokenRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validTokenRequestValues()
			test.mutate(values)

			_, err := ParseTokenRequest(values)
			if !errors.Is(err, test.expected) {
				t.Fatalf(
					"expected %v, got %v",
					test.expected,
					err,
				)
			}
		})
	}
}

func TestS256CodeChallengeMatchesRFCExample(
	t *testing.T,
) {
	challenge, err :=
		deriveS256CodeChallenge(testTokenVerifier)
	if err != nil {
		t.Fatalf(
			"derive S256 challenge: %v",
			err,
		)
	}

	if challenge != testTokenChallenge {
		t.Fatalf(
			"expected challenge %q, got %q",
			testTokenChallenge,
			challenge,
		)
	}
}

func validTokenRequestValues() url.Values {
	return url.Values{
		"grant_type": {
			"authorization_code",
		},
		"code": {
			testTokenCode,
		},
		"redirect_uri": {
			"https://portal.example.test/oauth/callback",
		},
		"code_verifier": {
			testTokenVerifier,
		},
		"client_id": {
			testTokenClientID,
		},
	}
}
