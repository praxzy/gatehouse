package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSignedIDTokenVerifiesWithPublishedJWK(
	t *testing.T,
) {
	privateKey := generateTestRSAKey(t, 2048)

	signingKey, err := ParseRSAPrivateKeyPEM(
		"verification-key-1",
		encodeTestPrivateKey(t, privateKey),
	)
	if err != nil {
		t.Fatalf("parse signing key: %v", err)
	}

	now := time.Date(
		2026,
		time.August,
		22,
		10,
		30,
		0,
		0,
		time.UTC,
	)

	expectedClaims := IDTokenClaims{
		Issuer:             "https://identity.example.com",
		Subject:            "user-123",
		Audience:           "ghc_test_client",
		IssuedAt:           now.Unix(),
		ExpiresAt:          now.Add(5 * time.Minute).Unix(),
		AuthenticationTime: now.Add(-time.Minute).Unix(),
		Nonce:              "browser-nonce-123",
	}

	token, err := signingKey.SignIDToken(
		expectedClaims,
	)
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf(
			"expected compact JWT with 3 parts, got %d",
			len(parts),
		)
	}

	headerBytes := decodeJWTPart(
		t,
		parts[0],
		"header",
	)

	var header idTokenHeader
	if err := json.Unmarshal(
		headerBytes,
		&header,
	); err != nil {
		t.Fatalf("decode ID token header: %v", err)
	}

	if header.Algorithm != "RS256" ||
		header.Type != "JWT" ||
		header.KeyID != "verification-key-1" {
		t.Fatalf(
			"unexpected ID token header: %+v",
			header,
		)
	}

	claimsBytes := decodeJWTPart(
		t,
		parts[1],
		"claims",
	)

	var actualClaims IDTokenClaims
	if err := json.Unmarshal(
		claimsBytes,
		&actualClaims,
	); err != nil {
		t.Fatalf("decode ID token claims: %v", err)
	}

	if actualClaims != expectedClaims {
		t.Fatalf(
			"unexpected claims: %+v",
			actualClaims,
		)
	}

	signature := decodeJWTPart(
		t,
		parts[2],
		"signature",
	)

	publicKey := publicKeyFromJWK(
		t,
		signingKey.PublicJWK(),
	)

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	if err := rsa.VerifyPKCS1v15(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
	); err != nil {
		t.Fatalf(
			"verify ID token with published JWK: %v",
			err,
		)
	}
}

func TestSignIDTokenRejectsInvalidClaims(
	t *testing.T,
) {
	signingKey, err := ParseRSAPrivateKeyPEM(
		"test-key",
		encodeTestPrivateKey(
			t,
			generateTestRSAKey(t, 2048),
		),
	)
	if err != nil {
		t.Fatalf("parse signing key: %v", err)
	}

	_, err = signingKey.SignIDToken(
		IDTokenClaims{
			Issuer:    "https://identity.example.com",
			Subject:   "user-123",
			Audience:  "ghc_test_client",
			IssuedAt:  100,
			ExpiresAt: 100,
		},
	)

	if err != ErrInvalidIDTokenClaims {
		t.Fatalf(
			"expected invalid claims, got %v",
			err,
		)
	}
}

func decodeJWTPart(
	t *testing.T,
	value string,
	name string,
) []byte {
	t.Helper()

	decoded, err :=
		base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf(
			"decode JWT %s: %v",
			name,
			err,
		)
	}

	return decoded
}

func publicKeyFromJWK(
	t *testing.T,
	jwk JWK,
) *rsa.PublicKey {
	t.Helper()

	if jwk.KeyType != "RSA" ||
		jwk.Use != "sig" ||
		jwk.Algorithm != "RS256" {
		t.Fatalf("unexpected JWK: %+v", jwk)
	}

	modulusBytes := decodeJWTPart(
		t,
		jwk.Modulus,
		"JWK modulus",
	)
	exponentBytes := decodeJWTPart(
		t,
		jwk.Exponent,
		"JWK exponent",
	)

	exponent := new(big.Int).SetBytes(exponentBytes)
	if !exponent.IsInt64() {
		t.Fatal("JWK exponent does not fit int64")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent.Int64()),
	}
}
