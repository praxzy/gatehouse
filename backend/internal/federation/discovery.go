package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxDiscoveryDocumentBytes int64 = 1 << 20

var (
	ErrInvalidDiscoveryClient = errors.New(
		"invalid upstream discovery client",
	)
	ErrDiscoveryUnavailable = errors.New(
		"upstream discovery unavailable",
	)
	ErrInvalidDiscoveryDocument = errors.New(
		"invalid upstream discovery document",
	)
)

type DiscoveryDocument struct {
	Issuer string `json:"issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	ResponseTypesSupported []string `json:"response_types_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`
	ScopesSupported        []string `json:"scopes_supported"`

	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

type DiscoveryClient struct {
	provider *ProviderHTTPClient
}

func NewDiscoveryClient(
	provider *ProviderHTTPClient,
) (*DiscoveryClient, error) {
	if provider == nil ||
		provider.httpClient == nil {
		return nil, ErrInvalidDiscoveryClient
	}

	return &DiscoveryClient{
		provider: provider,
	}, nil
}

func (client *DiscoveryClient) Discover(
	ctx context.Context,
	issuer string,
) (DiscoveryDocument, error) {
	if client == nil ||
		client.provider == nil {
		return DiscoveryDocument{},
			ErrInvalidDiscoveryClient
	}

	issuerURL, err := parseProviderURL(
		issuer,
		client.provider.policy,
	)
	if err != nil {
		return DiscoveryDocument{}, err
	}

	if issuerURL.RawQuery != "" ||
		issuerURL.ForceQuery ||
		issuerURL.RawPath != "" {
		return DiscoveryDocument{},
			ErrInvalidDiscoveryDocument
	}

	discoveryURL := *issuerURL
	discoveryURL.Path = strings.TrimRight(
		discoveryURL.Path,
		"/",
	) + "/.well-known/openid-configuration"

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		discoveryURL.String(),
		nil,
	)
	if err != nil {
		return DiscoveryDocument{},
			fmt.Errorf(
				"%w: create request",
				ErrDiscoveryUnavailable,
			)
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)

	response, err := client.provider.Do(request)
	if err != nil {
		return DiscoveryDocument{},
			fmt.Errorf(
				"%w: %v",
				ErrDiscoveryUnavailable,
				err,
			)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return DiscoveryDocument{},
			fmt.Errorf(
				"%w: status %d",
				ErrDiscoveryUnavailable,
				response.StatusCode,
			)
	}

	payload, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maxDiscoveryDocumentBytes+1,
		),
	)
	if err != nil {
		return DiscoveryDocument{},
			fmt.Errorf(
				"%w: read response",
				ErrDiscoveryUnavailable,
			)
	}

	if int64(len(payload)) >
		maxDiscoveryDocumentBytes {
		return DiscoveryDocument{},
			ErrInvalidDiscoveryDocument
	}

	decoder := json.NewDecoder(
		bytes.NewReader(payload),
	)

	var document DiscoveryDocument
	if err := decoder.Decode(&document); err != nil {
		return DiscoveryDocument{},
			ErrInvalidDiscoveryDocument
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DiscoveryDocument{},
			ErrInvalidDiscoveryDocument
	}

	if err := client.validateDocument(
		issuer,
		document,
	); err != nil {
		return DiscoveryDocument{}, err
	}

	return document, nil
}

func (client *DiscoveryClient) validateDocument(
	expectedIssuer string,
	document DiscoveryDocument,
) error {
	if document.Issuer != expectedIssuer {
		return ErrInvalidDiscoveryDocument
	}

	endpoints := []string{
		document.AuthorizationEndpoint,
		document.TokenEndpoint,
		document.JWKSURI,
	}

	for _, endpoint := range endpoints {
		if _, err := parseProviderURL(
			endpoint,
			client.provider.policy,
		); err != nil {
			return ErrInvalidDiscoveryDocument
		}
	}

	if !containsString(
		document.ResponseTypesSupported,
		"code",
	) {
		return ErrInvalidDiscoveryDocument
	}

	if len(document.GrantTypesSupported) > 0 &&
		!containsString(
			document.GrantTypesSupported,
			"authorization_code",
		) {
		return ErrInvalidDiscoveryDocument
	}

	if !containsString(
		document.ScopesSupported,
		"openid",
	) {
		return ErrInvalidDiscoveryDocument
	}

	if !containsString(
		document.IDTokenSigningAlgValuesSupported,
		"RS256",
	) {
		return ErrInvalidDiscoveryDocument
	}

	if len(
		document.TokenEndpointAuthMethodsSupported,
	) > 0 &&
		!containsString(
			document.TokenEndpointAuthMethodsSupported,
			"client_secret_basic",
		) {
		return ErrInvalidDiscoveryDocument
	}

	if !containsString(
		document.CodeChallengeMethodsSupported,
		"S256",
	) {
		return ErrInvalidDiscoveryDocument
	}

	return nil
}

func containsString(
	values []string,
	expected string,
) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}

	return false
}
