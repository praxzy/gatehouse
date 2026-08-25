package oidc

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestGenerateAuthorizationCodeProducesUniqueHashedCodes(
	t *testing.T,
) {
	firstCode, firstHash, err :=
		generateAuthorizationCode()
	if err != nil {
		t.Fatalf(
			"generate first authorization code: %v",
			err,
		)
	}

	secondCode, secondHash, err :=
		generateAuthorizationCode()
	if err != nil {
		t.Fatalf(
			"generate second authorization code: %v",
			err,
		)
	}

	if firstCode == secondCode {
		t.Fatal("generated authorization codes matched")
	}

	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("generated authorization code hashes matched")
	}

	if !validAuthorizationCode(firstCode) ||
		!validAuthorizationCode(secondCode) {
		t.Fatal("generated authorization code was invalid")
	}

	expectedHash := sha256.Sum256(
		[]byte(firstCode),
	)

	if !bytes.Equal(
		firstHash,
		expectedHash[:],
	) {
		t.Fatal(
			"authorization code hash did not match SHA-256",
		)
	}

	if bytes.Contains(
		firstHash,
		[]byte(firstCode),
	) {
		t.Fatal(
			"stored hash unexpectedly contained raw code",
		)
	}
}

func TestAuthorizationCodeValidationRejectsMalformedValues(
	t *testing.T,
) {
	values := []string{
		"",
		"ghac_",
		"wrong_prefix_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		"ghac_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",
		"ghac_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM!",
	}

	for _, value := range values {
		if validAuthorizationCode(value) {
			t.Fatalf(
				"accepted malformed authorization code %q",
				value,
			)
		}
	}
}
