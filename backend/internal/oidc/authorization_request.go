package oidc

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

const (
	minimumAuthorizationOpaqueLength = 16
	maximumAuthorizationOpaqueLength = 512
	maximumRedirectURILength         = 2048
)

var (
	ErrInvalidAuthorizationTarget = errors.New(
		"invalid authorization target",
	)
	ErrInvalidAuthorizationRequest = errors.New(
		"invalid authorization request",
	)
	ErrUnsupportedResponseType = errors.New(
		"unsupported authorization response type",
	)
	ErrInvalidAuthorizationScope = errors.New(
		"invalid authorization scope",
	)
	ErrPKCERequired = errors.New(
		"S256 PKCE is required",
	)

	clientIDPattern = regexp.MustCompile(
		`^ghc_[A-Za-z0-9_-]{32}$`,
	)
	pkceChallengePattern = regexp.MustCompile(
		`^[A-Za-z0-9_-]{43}$`,
	)
	opaqueAuthorizationValuePattern = regexp.MustCompile(
		`^[A-Za-z0-9._~-]+$`,
	)
)

type AuthorizationTarget struct {
	ClientID    string
	RedirectURI string
}

type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func ParseAuthorizationTarget(
	values url.Values,
) (AuthorizationTarget, error) {
	clientID, ok := requiredSingleton(
		values,
		"client_id",
	)
	if !ok || !clientIDPattern.MatchString(clientID) {
		return AuthorizationTarget{},
			ErrInvalidAuthorizationTarget
	}

	redirectURI, ok := requiredSingleton(
		values,
		"redirect_uri",
	)
	if !ok ||
		redirectURI == "" ||
		len(redirectURI) > maximumRedirectURILength ||
		redirectURI != strings.TrimSpace(redirectURI) {
		return AuthorizationTarget{},
			ErrInvalidAuthorizationTarget
	}

	return AuthorizationTarget{
		ClientID:    clientID,
		RedirectURI: redirectURI,
	}, nil
}

func ParseAuthorizationRequest(
	values url.Values,
) (AuthorizationRequest, error) {
	target, err := ParseAuthorizationTarget(values)
	if err != nil {
		return AuthorizationRequest{}, err
	}

	responseType, ok := requiredSingleton(
		values,
		"response_type",
	)
	if !ok {
		return AuthorizationRequest{},
			ErrInvalidAuthorizationRequest
	}
	if responseType != "code" {
		return AuthorizationRequest{},
			ErrUnsupportedResponseType
	}

	scopeValue, ok := requiredSingleton(
		values,
		"scope",
	)
	if !ok {
		return AuthorizationRequest{},
			ErrInvalidAuthorizationScope
	}

	scope, err := parseAuthorizationScope(
		scopeValue,
	)
	if err != nil {
		return AuthorizationRequest{}, err
	}

	state, ok := requiredSingleton(
		values,
		"state",
	)
	if !ok || !validAuthorizationOpaqueValue(state) {
		return AuthorizationRequest{},
			ErrInvalidAuthorizationRequest
	}

	nonce, ok := requiredSingleton(
		values,
		"nonce",
	)
	if !ok || !validAuthorizationOpaqueValue(nonce) {
		return AuthorizationRequest{},
			ErrInvalidAuthorizationRequest
	}

	codeChallenge, ok := requiredSingleton(
		values,
		"code_challenge",
	)
	if !ok ||
		!pkceChallengePattern.MatchString(
			codeChallenge,
		) {
		return AuthorizationRequest{}, ErrPKCERequired
	}

	codeChallengeMethod, ok := requiredSingleton(
		values,
		"code_challenge_method",
	)
	if !ok || codeChallengeMethod != "S256" {
		return AuthorizationRequest{}, ErrPKCERequired
	}

	return AuthorizationRequest{
		ClientID:            target.ClientID,
		RedirectURI:         target.RedirectURI,
		ResponseType:        responseType,
		Scope:               scope,
		State:               state,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}, nil
}

func parseAuthorizationScope(
	value string,
) ([]string, error) {
	parts := strings.Fields(value)

	if len(parts) == 0 ||
		strings.Join(parts, " ") != value {
		return nil, ErrInvalidAuthorizationScope
	}

	supported := map[string]struct{}{
		"openid":  {},
		"profile": {},
		"email":   {},
	}

	scope := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	hasOpenID := false

	for _, item := range parts {
		if _, ok := supported[item]; !ok {
			return nil, ErrInvalidAuthorizationScope
		}

		if _, duplicate := seen[item]; duplicate {
			return nil, ErrInvalidAuthorizationScope
		}

		seen[item] = struct{}{}
		scope = append(scope, item)

		if item == "openid" {
			hasOpenID = true
		}
	}

	if !hasOpenID {
		return nil, ErrInvalidAuthorizationScope
	}

	return scope, nil
}

func validAuthorizationOpaqueValue(
	value string,
) bool {
	return len(value) >=
		minimumAuthorizationOpaqueLength &&
		len(value) <=
			maximumAuthorizationOpaqueLength &&
		opaqueAuthorizationValuePattern.
			MatchString(value)
}

func requiredSingleton(
	values url.Values,
	name string,
) (string, bool) {
	items, exists := values[name]
	if !exists || len(items) != 1 {
		return "", false
	}

	return items[0], true
}
