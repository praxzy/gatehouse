package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const membershipInvitationTokenBytes = 32

var ErrInvalidMembershipInvitationToken = errors.New(
	"invalid membership invitation token",
)

func generateMembershipInvitationToken() (
	rawToken string,
	tokenHash []byte,
	err error,
) {
	tokenBytes := make(
		[]byte,
		membershipInvitationTokenBytes,
	)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, err
	}

	rawToken = base64.RawURLEncoding.EncodeToString(
		tokenBytes,
	)
	digest := sha256.Sum256(tokenBytes)

	return rawToken, digest[:], nil
}

func hashMembershipInvitationToken(
	rawToken string,
) ([]byte, error) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(
		rawToken,
	)
	if err != nil ||
		len(tokenBytes) != membershipInvitationTokenBytes {
		return nil, ErrInvalidMembershipInvitationToken
	}

	digest := sha256.Sum256(tokenBytes)
	return digest[:], nil
}
