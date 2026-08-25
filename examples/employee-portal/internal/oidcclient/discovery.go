package oidcclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const maximumProviderResponseBytes = 1024 * 1024

var ErrInvalidProvider = errors.New(
	"invalid OIDC provider metadata",
)

type Provider struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

type Client struct {
	issuer     string
	clientID   string
	secret     string
	redirect   string
	httpClient *http.Client
	now        func() time.Time
}

func New(
	issuer string,
	clientID string,
	secret string,
	redirectURI string,
	httpClient *http.Client,
) (*Client, error) {
	if issuer == "" ||
		clientID == "" ||
		secret == "" ||
		redirectURI == "" ||
		httpClient == nil ||
		!validIssuerURL(issuer) ||
		!validProviderURL(redirectURI) {
		return nil, ErrInvalidProvider
	}

	return &Client{
		issuer:     issuer,
		clientID:   clientID,
		secret:     secret,
		redirect:   redirectURI,
		httpClient: httpClient,
		now:        time.Now,
	}, nil
}

func validIssuerURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil &&
		validProviderURL(value) &&
		parsed.Path == "" &&
		parsed.RawPath == "" &&
		parsed.RawQuery == "" &&
		!parsed.ForceQuery
}

func (client *Client) Discover(
	ctx context.Context,
) (Provider, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		client.issuer+"/.well-known/openid-configuration",
		nil,
	)
	if err != nil {
		return Provider{}, fmt.Errorf(
			"create discovery request: %w",
			err,
		)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return Provider{}, fmt.Errorf(
			"request provider discovery: %w",
			err,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Provider{}, ErrInvalidProvider
	}

	var provider Provider
	decoder := json.NewDecoder(
		io.LimitReader(
			response.Body,
			maximumProviderResponseBytes,
		),
	)
	if err := decoder.Decode(&provider); err != nil {
		return Provider{}, ErrInvalidProvider
	}

	if err := validateProvider(client.issuer, provider); err != nil {
		return Provider{}, err
	}

	return provider, nil
}

func validateProvider(
	expectedIssuer string,
	provider Provider,
) error {
	if provider.Issuer != expectedIssuer ||
		!validProviderURL(provider.AuthorizationEndpoint) ||
		!validProviderURL(provider.TokenEndpoint) ||
		!validProviderURL(provider.JWKSURI) ||
		!slices.Contains(
			provider.ResponseTypesSupported,
			"code",
		) ||
		!slices.Contains(
			provider.GrantTypesSupported,
			"authorization_code",
		) ||
		!slices.Contains(
			provider.IDTokenSigningAlgorithmsSupported,
			"RS256",
		) ||
		!slices.Contains(
			provider.TokenEndpointAuthMethodsSupported,
			"client_secret_basic",
		) ||
		!slices.Contains(
			provider.CodeChallengeMethodsSupported,
			"S256",
		) {
		return ErrInvalidProvider
	}

	return nil
}

func validProviderURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return false
	}

	switch {
	case strings.EqualFold(parsed.Scheme, "https"):
		return true
	case strings.EqualFold(parsed.Scheme, "http") &&
		strings.EqualFold(parsed.Hostname(), "localhost"):
		return true
	default:
		return false
	}
}
