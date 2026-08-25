package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

const (
	accessTokenPrefix      = "ghat_"
	accessTokenRandomBytes = 32
	accessTokenLifetime    = 15 * time.Minute
	idTokenLifetime        = 5 * time.Minute
)

var ErrAccessTokenGeneration = errors.New(
	"generate access token",
)

func generateAccessToken() (
	string,
	[]byte,
	error,
) {
	randomBytes := make(
		[]byte,
		accessTokenRandomBytes,
	)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, ErrAccessTokenGeneration
	}

	rawToken := accessTokenPrefix +
		base64.RawURLEncoding.EncodeToString(
			randomBytes,
		)

	return rawToken, hashAccessToken(rawToken), nil
}

func hashAccessToken(rawToken string) []byte {
	hash := sha256.Sum256([]byte(rawToken))

	result := make([]byte, len(hash))
	copy(result, hash[:])

	return result
}

func validAccessToken(rawToken string) bool {
	if !strings.HasPrefix(
		rawToken,
		accessTokenPrefix,
	) {
		return false
	}

	encoded := strings.TrimPrefix(
		rawToken,
		accessTokenPrefix,
	)

	if len(encoded) != 43 {
		return false
	}

	decoded, err :=
		base64.RawURLEncoding.DecodeString(encoded)

	return err == nil &&
		len(decoded) == accessTokenRandomBytes
}
