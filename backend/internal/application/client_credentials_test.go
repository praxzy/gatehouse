package application

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateClientID(t *testing.T) {
	seen := make(map[string]struct{})

	for range 64 {
		clientID, err := GenerateClientID()
		if err != nil {
			t.Fatalf("generate client ID: %v", err)
		}

		if !strings.HasPrefix(
			clientID,
			clientIDPrefix,
		) {
			t.Fatalf(
				"client ID has unexpected prefix: %q",
				clientID,
			)
		}

		encoded := strings.TrimPrefix(
			clientID,
			clientIDPrefix,
		)

		randomBytes, err :=
			base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf(
				"decode client ID randomness: %v",
				err,
			)
		}

		if len(randomBytes) != clientIDRandomBytes {
			t.Fatalf(
				"expected %d random bytes, got %d",
				clientIDRandomBytes,
				len(randomBytes),
			)
		}

		if _, duplicate := seen[clientID]; duplicate {
			t.Fatal("generated a duplicate client ID")
		}

		seen[clientID] = struct{}{}
	}
}

func TestGenerateClientSecretStoresOnlyHashMaterial(
	t *testing.T,
) {
	rawSecret, secretHash, err :=
		GenerateClientSecret()
	if err != nil {
		t.Fatalf("generate client secret: %v", err)
	}

	if !strings.HasPrefix(
		rawSecret,
		clientSecretPrefix,
	) {
		t.Fatalf(
			"client secret has unexpected prefix: %q",
			rawSecret,
		)
	}

	encoded := strings.TrimPrefix(
		rawSecret,
		clientSecretPrefix,
	)

	randomBytes, err :=
		base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf(
			"decode client secret randomness: %v",
			err,
		)
	}

	if len(randomBytes) != clientSecretRawBytes {
		t.Fatalf(
			"expected %d random bytes, got %d",
			clientSecretRawBytes,
			len(randomBytes),
		)
	}

	if len(secretHash) != sha256.Size {
		t.Fatalf(
			"expected %d-byte hash, got %d",
			sha256.Size,
			len(secretHash),
		)
	}

	if bytes.Equal(
		secretHash,
		[]byte(rawSecret),
	) {
		t.Fatal("client secret hash exposed raw secret")
	}

	if !VerifyClientSecret(rawSecret, secretHash) {
		t.Fatal("generated client secret did not verify")
	}

	if VerifyClientSecret(
		rawSecret+"tampered",
		secretHash,
	) {
		t.Fatal("tampered client secret verified")
	}

	if VerifyClientSecret(rawSecret, []byte("short")) {
		t.Fatal("invalid-length hash verified")
	}
}

func TestClientSecretHashIsDeterministic(
	t *testing.T,
) {
	const rawSecret = "ghs_test-client-secret"

	first := HashClientSecret(rawSecret)
	second := HashClientSecret(rawSecret)

	if !bytes.Equal(first, second) {
		t.Fatal("same client secret produced different hashes")
	}

	if VerifyClientSecret(
		"ghs_different-client-secret",
		first,
	) {
		t.Fatal("different client secret verified")
	}
}
