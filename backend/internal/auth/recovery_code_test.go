package auth

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}

	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	seen := make(map[string]struct{}, len(codes))

	for _, code := range codes {
		if _, exists := seen[code.Code]; exists {
			t.Fatalf("duplicate recovery code %q", code.Code)
		}
		seen[code.Code] = struct{}{}

		if len(code.Hash) != 32 {
			t.Fatalf(
				"expected 32-byte hash, got %d",
				len(code.Hash),
			)
		}

		recalculated, err := HashRecoveryCode(
			strings.ToLower(code.Code),
		)
		if err != nil {
			t.Fatalf("hash recovery code: %v", err)
		}

		if !bytes.Equal(recalculated, code.Hash) {
			t.Fatal("recovery-code hash mismatch")
		}

		if bytes.Equal([]byte(code.Code), code.Hash) {
			t.Fatal("recovery code stored as plaintext")
		}
	}
}

func TestHashRecoveryCodeRejectsInvalidInput(t *testing.T) {
	testCases := []string{
		"",
		"TOO-SHORT",
		"00000-00000-00000-00000",
		"AAAAA-AAAAA-AAAAA-AAAA!",
	}

	for _, code := range testCases {
		t.Run(code, func(t *testing.T) {
			if _, err := HashRecoveryCode(code); err == nil {
				t.Fatal("expected invalid recovery code error")
			}
		})
	}
}
