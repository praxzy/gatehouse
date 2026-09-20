package federation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"testing"
)

type failingAuthorizationReader struct {
	err error
}

func (reader failingAuthorizationReader) Read(
	_ []byte,
) (int, error) {
	return 0, reader.err
}

func TestGenerateAuthorizationArtifacts(
	t *testing.T,
) {
	artifacts, err :=
		GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf(
			"generate authorization artifacts: %v",
			err,
		)
	}

	values := []struct {
		name  string
		value string
	}{
		{
			name:  "state",
			value: artifacts.State,
		},
		{
			name:  "nonce",
			value: artifacts.Nonce,
		},
		{
			name:  "PKCE verifier",
			value: artifacts.PKCEVerifier,
		},
	}

	for _, value := range values {
		t.Run(value.name, func(t *testing.T) {
			decoded, err :=
				base64.RawURLEncoding.DecodeString(
					value.value,
				)
			if err != nil {
				t.Fatalf(
					"decode value: %v",
					err,
				)
			}

			if len(decoded) !=
				authorizationRandomBytes {
				t.Fatalf(
					"unexpected entropy length: %d",
					len(decoded),
				)
			}

			if len(value.value) != 43 {
				t.Fatalf(
					"unexpected encoded length: %d",
					len(value.value),
				)
			}
		})
	}

	if artifacts.State == artifacts.Nonce ||
		artifacts.State == artifacts.PKCEVerifier ||
		artifacts.Nonce == artifacts.PKCEVerifier {
		t.Fatal(
			"authorization artifacts are not independent",
		)
	}

	expectedStateHash := sha256.Sum256(
		[]byte(artifacts.State),
	)
	if !bytes.Equal(
		artifacts.StateHash,
		expectedStateHash[:],
	) {
		t.Fatal("incorrect state hash")
	}

	expectedNonceHash := sha256.Sum256(
		[]byte(artifacts.Nonce),
	)
	if !bytes.Equal(
		artifacts.NonceHash,
		expectedNonceHash[:],
	) {
		t.Fatal("incorrect nonce hash")
	}

	expectedChallenge := sha256.Sum256(
		[]byte(artifacts.PKCEVerifier),
	)
	if artifacts.PKCEChallenge !=
		base64.RawURLEncoding.EncodeToString(
			expectedChallenge[:],
		) {
		t.Fatal("incorrect PKCE challenge")
	}
}

func TestGenerateAuthorizationArtifactsUsesFreshRandomness(
	t *testing.T,
) {
	first, err := GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf("generate first artifacts: %v", err)
	}

	second, err := GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf("generate second artifacts: %v", err)
	}

	if first.State == second.State ||
		first.Nonce == second.Nonce ||
		first.PKCEVerifier == second.PKCEVerifier {
		t.Fatal("authorization values were reused")
	}
}

func TestHashAuthorizationValues(
	t *testing.T,
) {
	artifacts, err := GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf("generate artifacts: %v", err)
	}

	stateHash, err := HashAuthorizationState(
		artifacts.State,
	)
	if err != nil {
		t.Fatalf("hash state: %v", err)
	}

	if !bytes.Equal(
		stateHash,
		artifacts.StateHash,
	) {
		t.Fatal("state hash changed")
	}

	nonceHash, err := HashAuthorizationNonce(
		artifacts.Nonce,
	)
	if err != nil {
		t.Fatalf("hash nonce: %v", err)
	}

	if !bytes.Equal(
		nonceHash,
		artifacts.NonceHash,
	) {
		t.Fatal("nonce hash changed")
	}
}

func TestHashAuthorizationValueRejectsInvalidInput(
	t *testing.T,
) {
	validBytes := bytes.Repeat(
		[]byte{0xff},
		authorizationRandomBytes,
	)
	validValue :=
		base64.RawURLEncoding.EncodeToString(
			validBytes,
		)

	tests := []struct {
		name  string
		value string
	}{
		{
			name: "empty",
		},
		{
			name:  "malformed",
			value: "not-base64!",
		},
		{
			name: "too short",
			value: base64.RawURLEncoding.
				EncodeToString(
					validBytes[:31],
				),
		},
		{
			name: "too long",
			value: base64.RawURLEncoding.
				EncodeToString(
					append(
						validBytes,
						0xff,
					),
				),
		},
		{
			name: "padded",
			value: base64.URLEncoding.
				EncodeToString(validBytes),
		},
		{
			name: "standard base64 alphabet",
			value: base64.RawStdEncoding.
				EncodeToString(validBytes),
		},
		{
			name:  "leading whitespace",
			value: " " + validValue,
		},
		{
			name:  "trailing whitespace",
			value: validValue + " ",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err :=
				HashAuthorizationState(
					test.value,
				); !errors.Is(
				err,
				ErrInvalidAuthorizationValue,
			) {
				t.Fatalf(
					"expected invalid value error, got %v",
					err,
				)
			}

			if _, err :=
				HashAuthorizationNonce(
					test.value,
				); !errors.Is(
				err,
				ErrInvalidAuthorizationValue,
			) {
				t.Fatalf(
					"expected invalid value error, got %v",
					err,
				)
			}
		})
	}
}

func TestGenerateAuthorizationArtifactsPropagatesRandomFailure(
	t *testing.T,
) {
	randomErr := errors.New("random source unavailable")

	_, err := generateAuthorizationArtifacts(
		failingAuthorizationReader{
			err: randomErr,
		},
	)
	if !errors.Is(
		err,
		ErrGenerateAuthorizationArtifacts,
	) {
		t.Fatalf(
			"expected generation error, got %v",
			err,
		)
	}
}

func TestGenerateAuthorizationArtifactsRejectsNilReader(
	t *testing.T,
) {
	_, err := generateAuthorizationArtifacts(nil)
	if !errors.Is(
		err,
		ErrGenerateAuthorizationArtifacts,
	) {
		t.Fatalf(
			"expected generation error, got %v",
			err,
		)
	}
}

var _ io.Reader = failingAuthorizationReader{}
