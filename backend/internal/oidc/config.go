package oidc

import (
	"errors"
	"net/url"
	"strings"
)

var ErrInvalidIssuer = errors.New(
	"invalid OIDC issuer",
)

type ProviderConfig struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string
}

func NewProviderConfig(
	rawIssuer string,
) (ProviderConfig, error) {
	if rawIssuer == "" ||
		rawIssuer != strings.TrimSpace(rawIssuer) {
		return ProviderConfig{}, ErrInvalidIssuer
	}

	parsed, err := url.Parse(rawIssuer)
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		parsed.Path != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery ||
		parsed.Fragment != "" {
		return ProviderConfig{}, ErrInvalidIssuer
	}

	switch {
	case strings.EqualFold(parsed.Scheme, "https"):
	case strings.EqualFold(parsed.Scheme, "http") &&
		strings.EqualFold(parsed.Hostname(), "localhost"):
	default:
		return ProviderConfig{}, ErrInvalidIssuer
	}

	return ProviderConfig{
		Issuer: rawIssuer,
		AuthorizationEndpoint: rawIssuer +
			"/oauth/authorize",
		TokenEndpoint: rawIssuer +
			"/oauth/token",
		UserInfoEndpoint: rawIssuer +
			"/oidc/userinfo",
		JWKSURI: rawIssuer +
			"/.well-known/jwks.json",
	}, nil

}
