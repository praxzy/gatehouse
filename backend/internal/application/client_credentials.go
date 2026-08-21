package application

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	clientIDPrefix       = "ghc_"
	clientSecretPrefix   = "ghs_"
	clientIDRandomBytes  = 24
	clientSecretRawBytes = 32
)

func GenerateClientID() (string, error) {
	clientID, err := generateCredential(
		clientIDPrefix,
		clientIDRandomBytes,
	)
	if err != nil {
		return "", fmt.Errorf(
			"generate client ID: %w",
			err,
		)
	}

	return clientID, nil
}

func GenerateClientSecret() (
	string,
	[]byte,
	error,
) {
	rawSecret, err := generateCredential(
		clientSecretPrefix,
		clientSecretRawBytes,
	)
	if err != nil {
		return "", nil, fmt.Errorf(
			"generate client secret: %w",
			err,
		)
	}

	return rawSecret, HashClientSecret(rawSecret), nil
}

func HashClientSecret(rawSecret string) []byte {
	hash := sha256.Sum256([]byte(rawSecret))

	result := make([]byte, len(hash))
	copy(result, hash[:])

	return result
}

func VerifyClientSecret(
	rawSecret string,
	expectedHash []byte,
) bool {
	if len(expectedHash) != sha256.Size {
		return false
	}

	actualHash := HashClientSecret(rawSecret)

	return subtle.ConstantTimeCompare(
		actualHash,
		expectedHash,
	) == 1
}

func generateCredential(
	prefix string,
	randomByteCount int,
) (string, error) {
	randomBytes := make([]byte, randomByteCount)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(
		randomBytes,
	)

	return prefix + encoded, nil
}
