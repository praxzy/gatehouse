package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
)

func TestParseRSAPrivateKeyPEMAndPublicJWK(
	t *testing.T,
) {
	privateKey := generateTestRSAKey(t, 2048)
	encoded := encodeTestPrivateKey(t, privateKey)

	signingKey, err := ParseRSAPrivateKeyPEM(
		"test-key-1",
		encoded,
	)
	if err != nil {
		t.Fatalf("parse signing key: %v", err)
	}

	if signingKey.KeyID() != "test-key-1" {
		t.Fatalf(
			"unexpected key ID %q",
			signingKey.KeyID(),
		)
	}

	jwk := signingKey.PublicJWK()

	if jwk.KeyType != "RSA" ||
		jwk.Use != "sig" ||
		jwk.KeyID != "test-key-1" ||
		jwk.Algorithm != "RS256" {
		t.Fatalf("unexpected JWK metadata: %+v", jwk)
	}

	modulus, err := base64.RawURLEncoding.DecodeString(
		jwk.Modulus,
	)
	if err != nil {
		t.Fatalf("decode JWK modulus: %v", err)
	}

	if new(big.Int).SetBytes(modulus).Cmp(
		privateKey.PublicKey.N,
	) != 0 {
		t.Fatal("JWK modulus does not match RSA key")
	}

	exponent, err :=
		base64.RawURLEncoding.DecodeString(
			jwk.Exponent,
		)
	if err != nil {
		t.Fatalf("decode JWK exponent: %v", err)
	}

	if new(big.Int).SetBytes(exponent).Int64() !=
		int64(privateKey.PublicKey.E) {
		t.Fatal("JWK exponent does not match RSA key")
	}
}

func TestParseRSAPrivateKeyPEMRejectsInvalidConfiguration(
	t *testing.T,
) {
	validKey := encodeTestPrivateKey(
		t,
		generateTestRSAKey(t, 2048),
	)

	invalidKeyIDs := []string{
		"",
		"key with spaces",
		"key/one",
		"key:one",
	}

	for _, keyID := range invalidKeyIDs {
		t.Run(
			"invalid key ID "+keyID,
			func(t *testing.T) {
				_, err := ParseRSAPrivateKeyPEM(
					keyID,
					validKey,
				)
				if !errors.Is(err, ErrInvalidKeyID) {
					t.Fatalf(
						"expected invalid key ID, got %v",
						err,
					)
				}
			},
		)
	}

	t.Run(
		"malformed PEM",
		func(t *testing.T) {
			_, err := ParseRSAPrivateKeyPEM(
				"test-key",
				[]byte("not a private key"),
			)
			if !errors.Is(
				err,
				ErrInvalidSigningKey,
			) {
				t.Fatalf(
					"expected invalid signing key, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"weak RSA key",
		func(t *testing.T) {
			weakKey := encodeTestPrivateKey(
				t,
				generateTestRSAKey(t, 1024),
			)

			_, err := ParseRSAPrivateKeyPEM(
				"weak-key",
				weakKey,
			)
			if !errors.Is(
				err,
				ErrInvalidSigningKey,
			) {
				t.Fatalf(
					"expected weak key rejection, got %v",
					err,
				)
			}
		},
	)
}

func generateTestRSAKey(
	t *testing.T,
	bits int,
) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		bits,
	)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	return privateKey
}

func encodeTestPrivateKey(
	t *testing.T,
	privateKey *rsa.PrivateKey,
) []byte {
	t.Helper()

	encoded, err := x509.MarshalPKCS8PrivateKey(
		privateKey,
	)
	if err != nil {
		t.Fatalf("encode RSA key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encoded,
	})
}
