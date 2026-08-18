package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func TestGenerateMembershipInvitationToken(t *testing.T) {
	firstToken, firstHash, err :=
		generateMembershipInvitationToken()
	if err != nil {
		t.Fatalf("generate first invitation token: %v", err)
	}

	secondToken, secondHash, err :=
		generateMembershipInvitationToken()
	if err != nil {
		t.Fatalf("generate second invitation token: %v", err)
	}

	if firstToken == secondToken {
		t.Fatal("expected independently generated tokens")
	}

	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("expected independently generated token hashes")
	}

	decodedToken, err :=
		base64.RawURLEncoding.DecodeString(firstToken)
	if err != nil {
		t.Fatalf("decode generated token: %v", err)
	}

	if len(decodedToken) != membershipInvitationTokenBytes {
		t.Fatalf(
			"expected %d token bytes, got %d",
			membershipInvitationTokenBytes,
			len(decodedToken),
		)
	}

	expectedHash := sha256.Sum256(decodedToken)
	if !bytes.Equal(firstHash, expectedHash[:]) {
		t.Fatal("generated hash does not match invitation token")
	}

	roundTripHash, err :=
		hashMembershipInvitationToken(firstToken)
	if err != nil {
		t.Fatalf("hash generated invitation token: %v", err)
	}

	if !bytes.Equal(roundTripHash, firstHash) {
		t.Fatal("round-trip invitation hash does not match")
	}
}

func TestHashMembershipInvitationTokenRejectsMalformedTokens(
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
				make(
					[]byte,
					membershipInvitationTokenBytes-1,
				),
			),
		},
		{
			name: "too long",
			token: base64.RawURLEncoding.EncodeToString(
				make(
					[]byte,
					membershipInvitationTokenBytes+1,
				),
			),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := hashMembershipInvitationToken(
				testCase.token,
			)

			if !errors.Is(
				err,
				ErrInvalidMembershipInvitationToken,
			) {
				t.Fatalf(
					"expected invalid invitation token, got %v",
					err,
				)
			}
		})
	}
}
