package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrInvalidTokenRequest = errors.New(
		"invalid token request",
	)
	ErrUnsupportedTokenGrantType = errors.New(
		"unsupported token grant type",
	)
	ErrInvalidPKCEVerifier = errors.New(
		"invalid PKCE verifier",
	)

	pkceVerifierPattern = regexp.MustCompile(
		`^[A-Za-z0-9._~-]{43,128}$`,
	)
)

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientID     string
}

func ParseTokenRequest(
	values url.Values,
) (TokenRequest, error) {
	grantType, ok := requiredSingleton(
		values,
		"grant_type",
	)
	if !ok {
		return TokenRequest{}, ErrInvalidTokenRequest
	}
	if grantType != "authorization_code" {
		return TokenRequest{},
			ErrUnsupportedTokenGrantType
	}

	code, ok := requiredSingleton(values, "code")
	if !ok || !validAuthorizationCode(code) {
		return TokenRequest{}, ErrInvalidTokenRequest
	}

	redirectURI, ok := requiredSingleton(
		values,
		"redirect_uri",
	)
	if !ok ||
		redirectURI == "" ||
		len(redirectURI) > maximumRedirectURILength ||
		redirectURI != strings.TrimSpace(redirectURI) {
		return TokenRequest{}, ErrInvalidTokenRequest
	}

	codeVerifier, ok := requiredSingleton(
		values,
		"code_verifier",
	)
	if !ok ||
		!pkceVerifierPattern.MatchString(codeVerifier) {
		return TokenRequest{}, ErrInvalidPKCEVerifier
	}

	clientID := ""
	if items, exists := values["client_id"]; exists {
		if len(items) != 1 ||
			!clientIDPattern.MatchString(items[0]) {
			return TokenRequest{}, ErrInvalidTokenRequest
		}

		clientID = items[0]
	}

	if _, supplied := values["client_secret"]; supplied {
		return TokenRequest{}, ErrInvalidTokenRequest
	}

	return TokenRequest{
		GrantType:    grantType,
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
		ClientID:     clientID,
	}, nil
}

func deriveS256CodeChallenge(
	verifier string,
) (string, error) {
	if !pkceVerifierPattern.MatchString(verifier) {
		return "", ErrInvalidPKCEVerifier
	}

	digest := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(
		digest[:],
	), nil
}
