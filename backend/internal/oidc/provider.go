package oidc

import "errors"

var ErrInvalidProviderConfiguration = errors.New(
	"invalid OIDC provider configuration",
)

type Provider struct {
	config     ProviderConfig
	signingKey *SigningKey
}

type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

type JSONWebKeySet struct {
	Keys []JWK `json:"keys"`
}

func NewProvider(
	config ProviderConfig,
	signingKey *SigningKey,
) (*Provider, error) {
	expectedConfig, err := NewProviderConfig(
		config.Issuer,
	)
	if err != nil ||
		expectedConfig != config ||
		signingKey == nil ||
		signingKey.privateKey == nil {
		return nil, ErrInvalidProviderConfiguration
	}

	return &Provider{
		config:     config,
		signingKey: signingKey,
	}, nil
}

func (provider *Provider) DiscoveryDocument() DiscoveryDocument {
	if provider == nil {
		return DiscoveryDocument{}
	}

	return DiscoveryDocument{
		Issuer: provider.config.Issuer,
		AuthorizationEndpoint: provider.config.
			AuthorizationEndpoint,
		TokenEndpoint: provider.config.TokenEndpoint,
		UserInfoEndpoint: provider.config.
			UserInfoEndpoint,
		JWKSURI: provider.config.JWKSURI,
		ResponseTypesSupported: []string{
			"code",
		},
		ResponseModesSupported: []string{
			"query",
		},
		GrantTypesSupported: []string{
			"authorization_code",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IDTokenSigningAlgorithmsSupported: []string{
			"RS256",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"none",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		ClaimsSupported: []string{
			"iss",
			"sub",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"nonce",
			"name",
			"email",
			"email_verified",
			"roles",
		},
	}
}

func (provider *Provider) JSONWebKeySet() JSONWebKeySet {
	if provider == nil ||
		provider.signingKey == nil {
		return JSONWebKeySet{
			Keys: []JWK{},
		}
	}

	return JSONWebKeySet{
		Keys: []JWK{
			provider.signingKey.PublicJWK(),
		},
	}
}
