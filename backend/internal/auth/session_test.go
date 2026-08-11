package auth

import (
	"encoding/base64"
	"errors"
	"testing"
)

func TestGenerateSessionToken(t *testing.T) {
	firstToken, firstHash, err := generateSessionToken()
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}

	secondToken, secondHash, err := generateSessionToken()
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}

	if firstToken == secondToken {
		t.Fatal("expected independently generated tokens")
	}

	if string(firstHash) == string(secondHash) {
		t.Fatal("expected independently generated token hashes")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(firstToken)
	if err != nil {
		t.Fatalf("decode generated token: %v", err)
	}

	if len(decoded) != sessionTokenBytes {
		t.Fatalf(
			"expected %d token bytes, got %d",
			sessionTokenBytes,
			len(decoded),
		)
	}

	if len(firstHash) != 32 {
		t.Fatalf("expected 32-byte token hash, got %d", len(firstHash))
	}
}

func TestHashSessionTokenIsDeterministic(t *testing.T) {
	token, generatedHash, err := generateSessionToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	recalculatedHash, err := hashSessionToken(token)
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}

	if string(generatedHash) != string(recalculatedHash) {
		t.Fatal("expected the same token to produce the same hash")
	}
}

func TestHashSessionTokenRejectsMalformedTokens(t *testing.T) {
	shortToken := base64.RawURLEncoding.EncodeToString(
		make([]byte, sessionTokenBytes-1),
	)

	testCases := []string{
		"",
		"not valid base64!",
		shortToken,
	}

	for _, token := range testCases {
		t.Run(token, func(t *testing.T) {
			_, err := hashSessionToken(token)
			if !errors.Is(err, ErrInvalidSession) {
				t.Fatalf(
					"expected ErrInvalidSession, got %v",
					err,
				)
			}
		})
	}
}
