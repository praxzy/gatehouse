package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

func oidcProviderFromEnvironment() (
	*oidc.Provider,
	error,
) {
	issuer := os.Getenv("OIDC_ISSUER")
	if strings.TrimSpace(issuer) == "" {
		return nil, errors.New(
			"OIDC_ISSUER is required",
		)
	}

	keyID := os.Getenv("OIDC_SIGNING_KEY_ID")
	if strings.TrimSpace(keyID) == "" {
		return nil, errors.New(
			"OIDC_SIGNING_KEY_ID is required",
		)
	}

	config, err := oidc.NewProviderConfig(issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"configure OIDC issuer: %w",
			err,
		)
	}

	encodedPrivateKey, err := oidcSigningPrivateKeyFromEnvironment()
	if err != nil {
		return nil, err
	}
	defer clear(encodedPrivateKey)

	signingKey, err := oidc.ParseRSAPrivateKeyPEM(
		keyID,
		encodedPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"configure OIDC signing key: %w",
			err,
		)
	}

	provider, err := oidc.NewProvider(
		config,
		signingKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create OIDC provider: %w",
			err,
		)
	}

	return provider, nil
}

func oidcSigningPrivateKeyFromEnvironment() ([]byte, error) {
	privateKeyFile := strings.TrimSpace(
		os.Getenv("OIDC_SIGNING_PRIVATE_KEY_FILE"),
	)
	encodedPrivateKey := strings.TrimSpace(
		os.Getenv("OIDC_SIGNING_PRIVATE_KEY_BASE64"),
	)

	if privateKeyFile != "" && encodedPrivateKey != "" {
		return nil, errors.New(
			"exactly one OIDC signing private key source must be configured",
		)
	}

	if encodedPrivateKey != "" {
		privateKey, err := base64.StdEncoding.DecodeString(
			encodedPrivateKey,
		)
		if err != nil {
			return nil, errors.New(
				"OIDC_SIGNING_PRIVATE_KEY_BASE64 must be valid base64",
			)
		}

		return privateKey, nil
	}

	if privateKeyFile == "" {
		return nil, errors.New(
			"OIDC signing private key is required",
		)
	}

	privateKey, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf(
			"read OIDC signing private key: %w",
			err,
		)
	}

	return privateKey, nil
}
