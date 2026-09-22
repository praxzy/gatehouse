package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

const (
	maxTokenResponseBytes = 1 << 20
	maxClientIDBytes      = 512
	maxClientSecretBytes  = 4096
	maxAuthorizationCode  = 4096
	maxAccessTokenBytes   = 16384
	maxIDTokenBytes       = 32768
)

var (
	ErrInvalidTokenClient = errors.New(
		"invalid upstream token client",
	)
	ErrInvalidTokenExchange = errors.New(
		"invalid upstream token exchange",
	)
	ErrTokenExchangeRejected = errors.New(
		"upstream token exchange rejected",
	)
	ErrTokenEndpointUnavailable = errors.New(
		"upstream token endpoint unavailable",
	)
	ErrInvalidTokenResponse = errors.New(
		"invalid upstream token response",
	)
)

type TokenClient struct {
	provider *ProviderHTTPClient
}

type TokenExchangeInput struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  []byte
	Code          string
	RedirectURI   string
	PKCEVerifier  string
}

type TokenResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	IDToken     string
	Scope       string
}

type tokenResponseDocument struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func NewTokenClient(
	provider *ProviderHTTPClient,
) (*TokenClient, error) {
	if provider == nil ||
		provider.httpClient == nil {
		return nil, ErrInvalidTokenClient
	}

	return &TokenClient{
		provider: provider,
	}, nil
}

func (client *TokenClient) Exchange(
	ctx context.Context,
	input TokenExchangeInput,
) (TokenResponse, error) {
	if client == nil ||
		client.provider == nil {
		return TokenResponse{},
			ErrInvalidTokenClient
	}

	if err := validateTokenExchangeInput(
		input,
		client.provider.policy,
	); err != nil {
		return TokenResponse{}, err
	}

	form := url.Values{}
	form.Set(
		"grant_type",
		"authorization_code",
	)
	form.Set("code", input.Code)
	form.Set(
		"redirect_uri",
		input.RedirectURI,
	)
	form.Set(
		"code_verifier",
		input.PKCEVerifier,
	)

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		input.TokenEndpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return TokenResponse{},
			ErrInvalidTokenExchange
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)
	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)

	// OAuth client_secret_basic requires form encoding before
	// constructing the HTTP Basic credentials.
	request.SetBasicAuth(
		url.QueryEscape(input.ClientID),
		url.QueryEscape(string(input.ClientSecret)),
	)

	response, err := client.provider.Do(request)
	if err != nil {
		return TokenResponse{},
			fmt.Errorf(
				"%w: request failed",
				ErrTokenEndpointUnavailable,
			)
	}
	defer response.Body.Close()

	if response.StatusCode >= 400 &&
		response.StatusCode < 500 {
		return TokenResponse{},
			ErrTokenExchangeRejected
	}

	if response.StatusCode != http.StatusOK {
		return TokenResponse{},
			fmt.Errorf(
				"%w: status %d",
				ErrTokenEndpointUnavailable,
				response.StatusCode,
			)
	}

	payload, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maxTokenResponseBytes+1,
		),
	)
	if err != nil {
		return TokenResponse{},
			ErrTokenEndpointUnavailable
	}

	if int64(len(payload)) >
		maxTokenResponseBytes {
		return TokenResponse{},
			ErrInvalidTokenResponse
	}

	decoder := json.NewDecoder(
		bytes.NewReader(payload),
	)

	var document tokenResponseDocument
	if err := decoder.Decode(&document); err != nil {
		return TokenResponse{},
			ErrInvalidTokenResponse
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return TokenResponse{},
			ErrInvalidTokenResponse
	}

	if !validReturnedToken(
		document.AccessToken,
		maxAccessTokenBytes,
	) ||
		!validReturnedToken(
			document.IDToken,
			maxIDTokenBytes,
		) ||
		!strings.EqualFold(
			document.TokenType,
			"Bearer",
		) ||
		document.ExpiresIn < 0 {
		return TokenResponse{},
			ErrInvalidTokenResponse
	}

	return TokenResponse{
		AccessToken: document.AccessToken,
		TokenType:   document.TokenType,
		ExpiresIn:   document.ExpiresIn,
		IDToken:     document.IDToken,
		Scope:       document.Scope,
	}, nil
}

func validateTokenExchangeInput(
	input TokenExchangeInput,
	policy ProviderNetworkPolicy,
) error {
	if _, err := parseProviderURL(
		input.TokenEndpoint,
		policy,
	); err != nil {
		return ErrInvalidTokenExchange
	}

	if !validSensitiveValue(
		input.ClientID,
		maxClientIDBytes,
	) ||
		len(input.ClientSecret) == 0 ||
		len(input.ClientSecret) >
			maxClientSecretBytes ||
		!utf8.Valid(input.ClientSecret) ||
		!validSensitiveValue(
			string(input.ClientSecret),
			maxClientSecretBytes,
		) ||
		!validSensitiveValue(
			input.Code,
			maxAuthorizationCode,
		) ||
		!validFederationRedirectURI(
			input.RedirectURI,
		) {
		return ErrInvalidTokenExchange
	}

	if _, err := hashAuthorizationValue(
		input.PKCEVerifier,
	); err != nil {
		return ErrInvalidTokenExchange
	}

	return nil
}

func validSensitiveValue(
	value string,
	maximumBytes int,
) bool {
	if value == "" ||
		len(value) > maximumBytes ||
		!utf8.ValidString(value) {
		return false
	}

	for _, character := range value {
		if character < 0x20 ||
			character == 0x7f {
			return false
		}
	}

	return true
}

func validReturnedToken(
	value string,
	maximumBytes int,
) bool {
	return validSensitiveValue(
		value,
		maximumBytes,
	) &&
		value == strings.TrimSpace(value)
}
