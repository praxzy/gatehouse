package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOIDCSigningPrivateKeyFromEnvironment(t *testing.T) {
	t.Run("loads base64 key", func(t *testing.T) {
		expected := []byte("base64 private key")

		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_FILE", "")
		t.Setenv(
			"OIDC_SIGNING_PRIVATE_KEY_BASE64",
			base64.StdEncoding.EncodeToString(expected),
		)

		actual, err := oidcSigningPrivateKeyFromEnvironment()
		if err != nil {
			t.Fatalf("load base64 signing key: %v", err)
		}

		if !bytes.Equal(actual, expected) {
			t.Fatal("loaded base64 signing key does not match")
		}
	})

	t.Run("loads file key", func(t *testing.T) {
		expected := []byte("file private key")
		path := filepath.Join(t.TempDir(), "signing-key.pem")

		if err := os.WriteFile(path, expected, 0o600); err != nil {
			t.Fatalf("write signing key fixture: %v", err)
		}

		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_FILE", path)
		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_BASE64", "")

		actual, err := oidcSigningPrivateKeyFromEnvironment()
		if err != nil {
			t.Fatalf("load file signing key: %v", err)
		}

		if !bytes.Equal(actual, expected) {
			t.Fatal("loaded file signing key does not match")
		}
	})

	t.Run("rejects both sources", func(t *testing.T) {
		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_FILE", "/tmp/key.pem")
		t.Setenv(
			"OIDC_SIGNING_PRIVATE_KEY_BASE64",
			base64.StdEncoding.EncodeToString([]byte("key")),
		)

		_, err := oidcSigningPrivateKeyFromEnvironment()
		if err == nil ||
			!strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("expected ambiguous source error, got %v", err)
		}
	})

	t.Run("rejects malformed base64", func(t *testing.T) {
		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_FILE", "")
		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_BASE64", "not-base64!")

		_, err := oidcSigningPrivateKeyFromEnvironment()
		if err == nil ||
			!strings.Contains(err.Error(), "valid base64") {
			t.Fatalf("expected base64 validation error, got %v", err)
		}
	})

	t.Run("rejects missing source", func(t *testing.T) {
		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_FILE", "")
		t.Setenv("OIDC_SIGNING_PRIVATE_KEY_BASE64", "")

		_, err := oidcSigningPrivateKeyFromEnvironment()
		if err == nil ||
			!strings.Contains(err.Error(), "is required") {
			t.Fatalf("expected missing key error, got %v", err)
		}
	})
}

func TestOIDCProviderLoadsBase64SigningKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	encodedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	t.Setenv("OIDC_ISSUER", "https://issuer.example.com")
	t.Setenv("OIDC_SIGNING_KEY_ID", "test-rs256-v1")
	t.Setenv("OIDC_SIGNING_PRIVATE_KEY_FILE", "")
	t.Setenv(
		"OIDC_SIGNING_PRIVATE_KEY_BASE64",
		base64.StdEncoding.EncodeToString(encodedPEM),
	)

	provider, err := oidcProviderFromEnvironment()
	if err != nil {
		t.Fatalf("create provider from base64 key: %v", err)
	}

	keySet := provider.JSONWebKeySet()
	if len(keySet.Keys) != 1 {
		t.Fatalf("expected one published key, got %d", len(keySet.Keys))
	}

	if keySet.Keys[0].KeyID != "test-rs256-v1" {
		t.Fatalf("unexpected key ID %q", keySet.Keys[0].KeyID)
	}
}
