package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func TestGenerateEmailVerificationToken(t *testing.T) {
	firstToken, firstHash, err := generateEmailVerificationToken()
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}

	secondToken, secondHash, err := generateEmailVerificationToken()
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}

	if firstToken == secondToken {
		t.Fatal("expected independently generated tokens")
	}

	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("expected independently generated token hashes")
	}

	decodedToken, err := base64.RawURLEncoding.DecodeString(firstToken)
	if err != nil {
		t.Fatalf("decode generated token: %v", err)
	}

	if len(decodedToken) != emailVerificationTokenBytes {
		t.Fatalf(
			"expected %d token bytes, got %d",
			emailVerificationTokenBytes,
			len(decodedToken),
		)
	}

	expectedHash := sha256.Sum256(decodedToken)
	if !bytes.Equal(firstHash, expectedHash[:]) {
		t.Fatal("generated token hash does not match its token")
	}

	roundTripHash, err := hashEmailVerificationToken(firstToken)
	if err != nil {
		t.Fatalf("hash generated token: %v", err)
	}

	if !bytes.Equal(roundTripHash, firstHash) {
		t.Fatal("round-trip token hash does not match")
	}
}

func TestHashEmailVerificationTokenRejectsMalformedTokens(
	t *testing.T,
) {
	testCases := []struct {
		name  string
		token string
	}{
		{
			name:  "empty",
			token: "",
		},
		{
			name:  "invalid base64",
			token: "not-valid-base64!",
		},
		{
			name: "too short",
			token: base64.RawURLEncoding.EncodeToString(
				make([]byte, emailVerificationTokenBytes-1),
			),
		},
		{
			name: "too long",
			token: base64.RawURLEncoding.EncodeToString(
				make([]byte, emailVerificationTokenBytes+1),
			),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := hashEmailVerificationToken(
				testCase.token,
			)

			if !errors.Is(
				err,
				ErrInvalidEmailVerificationToken,
			) {
				t.Fatalf(
					"expected ErrInvalidEmailVerificationToken, got %v",
					err,
				)
			}
		})
	}
}
