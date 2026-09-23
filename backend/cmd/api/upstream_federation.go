package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/federation"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type upstreamFederationServices struct {
	authorization *federation.AuthorizationService
	callback      *federation.AuthorizationCallbackService
	management    *federation.ManagementService
}

func upstreamFederationServicesFromEnvironment(
	pool *pgxpool.Pool,
	authentication *auth.Service,
	auditWriter audit.EventWriter,
) (upstreamFederationServices, error) {
	redirectURI := strings.TrimSpace(
		os.Getenv("UPSTREAM_OIDC_REDIRECT_URI"),
	)

	// Federation remains optional unless explicitly configured.
	if redirectURI == "" {
		return upstreamFederationServices{}, nil
	}

	keyID := strings.TrimSpace(
		os.Getenv("UPSTREAM_OIDC_ENCRYPTION_KEY_ID"),
	)
	encodedKey := strings.TrimSpace(
		os.Getenv("UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64"),
	)

	if keyID == "" || encodedKey == "" {
		return upstreamFederationServices{}, errors.New(
			"upstream OIDC encryption configuration is required",
		)
	}

	key, err := base64.StdEncoding.DecodeString(
		encodedKey,
	)
	if err != nil {
		return upstreamFederationServices{}, errors.New(
			"UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64 is invalid",
		)
	}
	defer clear(key)

	secretCipher, err :=
		federation.NewAESGCMSecretCipher(
			keyID,
			key,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream OIDC secret cipher: %w",
			err,
		)
	}

	allowHTTP, err := optionalEnvironmentBool(
		"UPSTREAM_OIDC_ALLOW_HTTP",
	)
	if err != nil {
		return upstreamFederationServices{}, err
	}

	allowPrivateAddresses, err :=
		optionalEnvironmentBool(
			"UPSTREAM_OIDC_ALLOW_PRIVATE_ADDRESSES",
		)
	if err != nil {
		return upstreamFederationServices{}, err
	}

	providerHTTP :=
		federation.NewProviderHTTPClient(
			federation.ProviderNetworkPolicy{
				AllowHTTP: allowHTTP,

				AllowPrivateAddresses: allowPrivateAddresses,
			},
		)

	discovery, err :=
		federation.NewDiscoveryClient(
			providerHTTP,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream OIDC discovery client: %w",
			err,
		)
	}

	tokenClient, err :=
		federation.NewTokenClient(
			providerHTTP,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream OIDC token client: %w",
			err,
		)
	}

	jwksClient, err :=
		federation.NewJWKSClient(
			providerHTTP,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream OIDC JWKS client: %w",
			err,
		)
	}

	idTokenVerifier, err :=
		federation.NewIDTokenVerifier(
			jwksClient,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream ID token verifier: %w",
			err,
		)
	}

	queries := store.New(pool)

	management, err :=
		federation.NewManagementService(
			pool,
			discovery,
			secretCipher,
			auditWriter,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream federation management service: %w",
			err,
		)
	}

	authorization, err :=
		federation.NewAuthorizationService(
			queries,
			discovery,
			secretCipher,
			redirectURI,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream authorization service: %w",
			err,
		)
	}

	callback, err :=
		federation.NewAuthorizationCallbackService(
			queries,
			discovery,
			tokenClient,
			idTokenVerifier,
			secretCipher,
			authentication,
			redirectURI,
		)
	if err != nil {
		return upstreamFederationServices{}, fmt.Errorf(
			"create upstream callback service: %w",
			err,
		)
	}

	return upstreamFederationServices{
		authorization: authorization,
		callback:      callback,
		management:    management,
	}, nil
}

func optionalEnvironmentBool(
	name string,
) (bool, error) {
	value := strings.TrimSpace(
		os.Getenv(name),
	)
	if value == "" {
		return false, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf(
			"%s must be a boolean: %w",
			name,
			err,
		)
	}

	return parsed, nil
}
