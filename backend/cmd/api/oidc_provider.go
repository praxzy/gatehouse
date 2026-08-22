package main

import (
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

	privateKeyFile := strings.TrimSpace(
		os.Getenv(
			"OIDC_SIGNING_PRIVATE_KEY_FILE",
		),
	)
	if privateKeyFile == "" {
		return nil, errors.New(
			"OIDC_SIGNING_PRIVATE_KEY_FILE is required",
		)
	}

	config, err := oidc.NewProviderConfig(issuer)
	if err != nil {
		return nil, fmt.Errorf(
			"configure OIDC issuer: %w",
			err,
		)
	}

	encodedPrivateKey, err := os.ReadFile(
		privateKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read OIDC signing private key: %w",
			err,
		)
	}

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
