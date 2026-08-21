package application

import (
	"errors"
	"net/url"
	"strings"
)

const (
	maxRedirectURICount  = 20
	maxRedirectURILength = 2048
)

var (
	ErrInvalidRedirectURI   = errors.New("invalid redirect URI")
	ErrDuplicateRedirectURI = errors.New("duplicate redirect URI")
)

func ValidateRedirectURIs(
	values []string,
) ([]string, error) {
	if len(values) == 0 ||
		len(values) > maxRedirectURICount {
		return nil, ErrInvalidRedirectURI
	}

	validated := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		if err := validateRedirectURI(value); err != nil {
			return nil, err
		}

		if _, duplicate := seen[value]; duplicate {
			return nil, ErrDuplicateRedirectURI
		}

		seen[value] = struct{}{}
		validated = append(validated, value)
	}

	return validated, nil
}

func IsRedirectURIRegistered(
	requested string,
	registered []string,
) bool {
	for _, candidate := range registered {
		if requested == candidate {
			return true
		}
	}

	return false
}

func validateRedirectURI(value string) error {
	if value == "" ||
		len(value) > maxRedirectURILength ||
		value != strings.TrimSpace(value) ||
		strings.Contains(value, "#") {
		return ErrInvalidRedirectURI
	}

	parsed, err := url.ParseRequestURI(value)
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Opaque != "" ||
		parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil {
		return ErrInvalidRedirectURI
	}

	switch {
	case strings.EqualFold(parsed.Scheme, "https"):
		return nil

	case strings.EqualFold(parsed.Scheme, "http") &&
		strings.EqualFold(parsed.Hostname(), "localhost"):
		return nil

	default:
		return ErrInvalidRedirectURI
	}
}
