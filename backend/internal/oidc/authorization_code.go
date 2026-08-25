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
	authorizationCodePrefix      = "ghac_"
	authorizationCodeRandomBytes = 32
	authorizationCodeLifetime    = time.Minute
)

var ErrAuthorizationCodeGeneration = errors.New(
	"generate authorization code",
)

func generateAuthorizationCode() (
	string,
	[]byte,
	error,
) {
	randomBytes := make(
		[]byte,
		authorizationCodeRandomBytes,
	)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, ErrAuthorizationCodeGeneration
	}

	rawCode := authorizationCodePrefix +
		base64.RawURLEncoding.EncodeToString(
			randomBytes,
		)

	return rawCode, hashAuthorizationCode(rawCode), nil
}

func hashAuthorizationCode(rawCode string) []byte {
	hash := sha256.Sum256([]byte(rawCode))

	result := make([]byte, len(hash))
	copy(result, hash[:])

	return result
}

func validAuthorizationCode(rawCode string) bool {
	if !strings.HasPrefix(
		rawCode,
		authorizationCodePrefix,
	) {
		return false
	}

	encoded := strings.TrimPrefix(
		rawCode,
		authorizationCodePrefix,
	)

	if len(encoded) != 43 {
		return false
	}

	decoded, err :=
		base64.RawURLEncoding.DecodeString(encoded)

	return err == nil &&
		len(decoded) == authorizationCodeRandomBytes
}
