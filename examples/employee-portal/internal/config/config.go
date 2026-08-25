package config

import (
	"errors"
	"net/url"
	"strings"
)

var ErrInvalidConfiguration = errors.New(
	"invalid employee portal configuration",
)

type Config struct {
	HTTPAddress         string
	Issuer              string
	ClientID            string
	ClientSecret        string
	RedirectURI         string
	SessionCookieSecure bool
}

type Environment func(string) string

func Load(environment Environment) (Config, error) {
	if environment == nil {
		return Config{}, ErrInvalidConfiguration
	}

	secure, err := parseBoolean(
		environment("EMPLOYEE_PORTAL_COOKIE_SECURE"),
	)
	if err != nil {
		return Config{}, err
	}

	configuration := Config{
		HTTPAddress: strings.TrimSpace(
			environment("EMPLOYEE_PORTAL_HTTP_ADDR"),
		),
		Issuer: strings.TrimSpace(
			environment("EMPLOYEE_PORTAL_OIDC_ISSUER"),
		),
		ClientID: strings.TrimSpace(
			environment("EMPLOYEE_PORTAL_OIDC_CLIENT_ID"),
		),
		ClientSecret: environment(
			"EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET",
		),
		RedirectURI: strings.TrimSpace(
			environment("EMPLOYEE_PORTAL_OIDC_REDIRECT_URI"),
		),
		SessionCookieSecure: secure,
	}

	if configuration.HTTPAddress == "" ||
		configuration.ClientID == "" ||
		configuration.ClientSecret == "" ||
		configuration.ClientSecret !=
			strings.TrimSpace(configuration.ClientSecret) ||
		!validURL(configuration.Issuer, true) ||
		!validURL(configuration.RedirectURI, false) {
		return Config{}, ErrInvalidConfiguration
	}

	return configuration, nil
}

func parseBoolean(value string) (bool, error) {
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, ErrInvalidConfiguration
	}
}

func validURL(value string, issuer bool) bool {
	parsed, err := url.Parse(value)
	if err != nil ||
		value == "" ||
		parsed.Scheme == "" ||
		parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return false
	}

	if issuer && (parsed.Path != "" ||
		parsed.RawPath != "" ||
		parsed.RawQuery != "" ||
		parsed.ForceQuery) {
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
