package oidcclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestExchangeAuthorizationCodeUsesBasicAuthAndPKCE(
	t *testing.T,
) {
	httpClient := &http.Client{
		Transport: roundTripFunc(func(
			request *http.Request,
		) (*http.Response, error) {
			clientID, secret, ok := request.BasicAuth()
			if !ok ||
				clientID != "employee-client" ||
				secret != "employee-secret" {
				t.Fatalf("unexpected client authentication")
			}

			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatalf("read token request: %v", err)
			}

			values, err := urlParseQuery(string(body))
			if err != nil {
				t.Fatalf("parse token form: %v", err)
			}
			if values.Get("grant_type") !=
				"authorization_code" ||
				values.Get("code") != "code-value" ||
				values.Get("redirect_uri") !=
					"https://portal.example.test/oauth/callback" ||
				values.Get("code_verifier") != "verifier-value" {
				t.Fatalf("unexpected token form: %v", values)
			}

			return jsonResponse(`{
                "access_token": "access-token",
                "token_type": "Bearer",
                "expires_in": 900,
                "id_token": "header.claims.signature",
                "scope": "openid profile email"
            }`), nil
		}),
	}

	client, err := New(
		"https://id.example.test",
		"employee-client",
		"employee-secret",
		"https://portal.example.test/oauth/callback",
		httpClient,
	)
	if err != nil {
		t.Fatalf("create OIDC client: %v", err)
	}

	tokens, err := client.ExchangeAuthorizationCode(
		context.Background(),
		Provider{
			TokenEndpoint: "https://id.example.test/oauth/token",
		},
		"code-value",
		"verifier-value",
	)
	if err != nil {
		t.Fatalf("exchange authorization code: %v", err)
	}

	if tokens.AccessToken != "access-token" ||
		tokens.IDToken != "header.claims.signature" {
		t.Fatalf("unexpected token response: %#v", tokens)
	}
}

func TestVerifyIDTokenUsesPublishedJWKAndAllBindings(
	t *testing.T,
) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	now := time.Date(
		2026,
		time.August,
		25,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	rawToken := signTestIDToken(
		t,
		privateKey,
		"employee-key",
		idTokenClaims{
			Issuer:             "https://id.example.test",
			Subject:            "user-123",
			Audience:           audience{"employee-client"},
			ExpiresAt:          now.Add(5 * time.Minute).Unix(),
			IssuedAt:           now.Unix(),
			AuthenticationTime: now.Add(-time.Minute).Unix(),
			Nonce:              "expected-nonce",
			Name:               "Alice Example",
			Email:              "alice@example.test",
			EmailVerified:      true,
			Roles:              []string{"Admin", "Member"},
		},
	)

	httpClient := &http.Client{
		Transport: roundTripFunc(func(
			request *http.Request,
		) (*http.Response, error) {
			return jsonResponse(testJWKS(
				t,
				privateKey,
				"employee-key",
			)), nil
		}),
	}

	client, err := New(
		"https://id.example.test",
		"employee-client",
		"employee-secret",
		"https://portal.example.test/oauth/callback",
		httpClient,
	)
	if err != nil {
		t.Fatalf("create OIDC client: %v", err)
	}
	client.now = func() time.Time { return now }

	identity, err := client.VerifyIDToken(
		context.Background(),
		Provider{
			Issuer:  "https://id.example.test",
			JWKSURI: "https://id.example.test/.well-known/jwks.json",
		},
		rawToken,
		"expected-nonce",
	)
	if err != nil {
		t.Fatalf("verify ID token: %v", err)
	}

	if identity.Subject != "user-123" ||
		identity.Name != "Alice Example" ||
		identity.Email != "alice@example.test" ||
		len(identity.Roles) != 2 ||
		identity.Roles[0] != "Admin" {
		t.Fatalf("unexpected identity: %#v", identity)
	}
}

func TestVerifyIDTokenRejectsNonceMismatch(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	now := time.Now().UTC()
	rawToken := signTestIDToken(
		t,
		privateKey,
		"employee-key",
		idTokenClaims{
			Issuer:             "https://id.example.test",
			Subject:            "user-123",
			Audience:           audience{"employee-client"},
			ExpiresAt:          now.Add(5 * time.Minute).Unix(),
			IssuedAt:           now.Unix(),
			AuthenticationTime: now.Add(-time.Minute).Unix(),
			Nonce:              "attacker-nonce",
			Name:               "Alice",
			Email:              "alice@example.test",
			EmailVerified:      true,
			Roles:              []string{"Admin"},
		},
	)

	client, err := New(
		"https://id.example.test",
		"employee-client",
		"employee-secret",
		"https://portal.example.test/oauth/callback",
		&http.Client{
			Transport: roundTripFunc(func(
				request *http.Request,
			) (*http.Response, error) {
				return jsonResponse(testJWKS(
					t,
					privateKey,
					"employee-key",
				)), nil
			}),
		},
	)
	if err != nil {
		t.Fatalf("create OIDC client: %v", err)
	}
	client.now = func() time.Time { return now }

	_, err = client.VerifyIDToken(
		context.Background(),
		Provider{
			Issuer:  "https://id.example.test",
			JWKSURI: "https://id.example.test/jwks",
		},
		rawToken,
		"expected-nonce",
	)
	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("expected ErrInvalidIDToken, got %v", err)
	}
}

func signTestIDToken(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	keyID string,
	claims idTokenClaims,
) string {
	t.Helper()

	header, err := json.Marshal(idTokenHeader{
		Algorithm: "RS256",
		Type:      "JWT",
		KeyID:     keyID,
	})
	if err != nil {
		t.Fatalf("marshal JWT header: %v", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal JWT claims: %v", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		digest[:],
	)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	return signingInput + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

func testJWKS(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	keyID string,
) string {
	t.Helper()

	exponent := big.NewInt(
		int64(privateKey.PublicKey.E),
	).Bytes()

	encoded, err := json.Marshal(jsonWebKeySet{
		Keys: []jsonWebKey{
			{
				KeyType:   "RSA",
				Use:       "sig",
				KeyID:     keyID,
				Algorithm: "RS256",
				Modulus: base64.RawURLEncoding.EncodeToString(
					privateKey.PublicKey.N.Bytes(),
				),
				Exponent: base64.RawURLEncoding.EncodeToString(
					exponent,
				),
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	return string(encoded)
}

func urlParseQuery(value string) (url.Values, error) {
	return url.ParseQuery(value)
}
