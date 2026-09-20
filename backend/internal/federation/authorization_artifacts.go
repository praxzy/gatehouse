package federation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const authorizationRandomBytes = 32

var (
	ErrGenerateAuthorizationArtifacts = errors.New(
		"generate upstream authorization artifacts",
	)
	ErrInvalidAuthorizationValue = errors.New(
		"invalid upstream authorization value",
	)
)

type AuthorizationArtifacts struct {
	State         string
	StateHash     []byte
	Nonce         string
	NonceHash     []byte
	PKCEVerifier  string
	PKCEChallenge string
}

func GenerateAuthorizationArtifacts() (
	AuthorizationArtifacts,
	error,
) {
	return generateAuthorizationArtifacts(
		rand.Reader,
	)
}

func generateAuthorizationArtifacts(
	random io.Reader,
) (AuthorizationArtifacts, error) {
	if random == nil {
		return AuthorizationArtifacts{},
			ErrGenerateAuthorizationArtifacts
	}

	state, err := generateAuthorizationValue(
		random,
	)
	if err != nil {
		return AuthorizationArtifacts{},
			fmt.Errorf(
				"%w: state",
				ErrGenerateAuthorizationArtifacts,
			)
	}

	nonce, err := generateAuthorizationValue(
		random,
	)
	if err != nil {
		return AuthorizationArtifacts{},
			fmt.Errorf(
				"%w: nonce",
				ErrGenerateAuthorizationArtifacts,
			)
	}

	verifier, err := generateAuthorizationValue(
		random,
	)
	if err != nil {
		return AuthorizationArtifacts{},
			fmt.Errorf(
				"%w: PKCE verifier",
				ErrGenerateAuthorizationArtifacts,
			)
	}

	stateHash := sha256.Sum256(
		[]byte(state),
	)
	nonceHash := sha256.Sum256(
		[]byte(nonce),
	)
	challengeHash := sha256.Sum256(
		[]byte(verifier),
	)

	return AuthorizationArtifacts{
		State:         state,
		StateHash:     append([]byte(nil), stateHash[:]...),
		Nonce:         nonce,
		NonceHash:     append([]byte(nil), nonceHash[:]...),
		PKCEVerifier:  verifier,
		PKCEChallenge: base64.RawURLEncoding.EncodeToString(challengeHash[:]),
	}, nil
}

func HashAuthorizationState(
	state string,
) ([]byte, error) {
	return hashAuthorizationValue(state)
}

func HashAuthorizationNonce(
	nonce string,
) ([]byte, error) {
	return hashAuthorizationValue(nonce)
}

func generateAuthorizationValue(
	random io.Reader,
) (string, error) {
	value := make(
		[]byte,
		authorizationRandomBytes,
	)

	if _, err := io.ReadFull(
		random,
		value,
	); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(
		value,
	), nil
}

func hashAuthorizationValue(
	value string,
) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(
		value,
	)
	if err != nil ||
		len(decoded) != authorizationRandomBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidAuthorizationValue
	}

	hash := sha256.Sum256(
		[]byte(value),
	)

	return append([]byte(nil), hash[:]...), nil
}
