package oidc

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestGenerateAccessTokenProducesUniqueHashedTokens(
	t *testing.T,
) {
	firstToken, firstHash, err :=
		generateAccessToken()
	if err != nil {
		t.Fatalf(
			"generate first access token: %v",
			err,
		)
	}

	secondToken, secondHash, err :=
		generateAccessToken()
	if err != nil {
		t.Fatalf(
			"generate second access token: %v",
			err,
		)
	}

	if firstToken == secondToken {
		t.Fatal("generated access tokens matched")
	}

	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("generated access token hashes matched")
	}

	if !validAccessToken(firstToken) ||
		!validAccessToken(secondToken) {
		t.Fatal("generated access token was invalid")
	}

	expectedHash := sha256.Sum256(
		[]byte(firstToken),
	)

	if !bytes.Equal(
		firstHash,
		expectedHash[:],
	) {
		t.Fatal(
			"access token hash did not match SHA-256",
		)
	}
}

func TestAccessTokenValidationRejectsMalformedValues(
	t *testing.T,
) {
	values := []string{
		"",
		"ghat_",
		"wrong_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"ghat_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",
		"ghat_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM!",
	}

	for _, value := range values {
		if validAccessToken(value) {
			t.Fatalf(
				"accepted malformed access token %q",
				value,
			)
		}
	}
}
