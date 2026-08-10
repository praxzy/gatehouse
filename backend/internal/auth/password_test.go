package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	encodedHash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if !strings.HasPrefix(encodedHash, "$argon2id$") {
		t.Fatalf("expected Argon2id hash, got %q", encodedHash)
	}

	matches, err := VerifyPassword(
		"correct horse battery staple",
		encodedHash,
	)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if !matches {
		t.Fatal("expected password to match")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	encodedHash, err := HashPassword("correct password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	matches, err := VerifyPassword("wrong password", encodedHash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if matches {
		t.Fatal("expected wrong password not to match")
	}
}

func TestHashPasswordUsesUniqueSalt(t *testing.T) {
	firstHash, err := HashPassword("same password")
	if err != nil {
		t.Fatalf("hash first password: %v", err)
	}

	secondHash, err := HashPassword("same password")
	if err != nil {
		t.Fatalf("hash second password: %v", err)
	}

	if firstHash == secondHash {
		t.Fatal("expected unique hashes for the same password")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	testCases := []string{
		"",
		"plain-text-password",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=999999999,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaA",
	}

	for _, encodedHash := range testCases {
		t.Run(encodedHash, func(t *testing.T) {
			matches, err := VerifyPassword("password", encodedHash)

			if matches {
				t.Fatal("expected malformed hash not to match")
			}

			if !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf(
					"expected ErrInvalidPasswordHash, got %v",
					err,
				)
			}
		})
	}
}

func BenchmarkHashPassword(b *testing.B) {
	b.ReportAllocs()

	for range b.N {
		if _, err := HashPassword("benchmark password value"); err != nil {
			b.Fatalf("hash password: %v", err)
		}
	}
}
