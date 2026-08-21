package application

import (
	"errors"
	"testing"
)

func TestValidateRedirectURIs(t *testing.T) {
	t.Run("accepts HTTPS and localhost development URIs", func(t *testing.T) {
		input := []string{
			"https://portal.example.com/oidc/callback",
			"https://portal.example.com/oidc/callback?source=gatehouse",
			"http://localhost:5173/auth/callback",
		}

		result, err := ValidateRedirectURIs(input)
		if err != nil {
			t.Fatalf("validate redirect URIs: %v", err)
		}

		if len(result) != len(input) {
			t.Fatalf(
				"expected %d redirect URIs, got %d",
				len(input),
				len(result),
			)
		}

		for index := range input {
			if result[index] != input[index] {
				t.Fatalf(
					"redirect URI changed from %q to %q",
					input[index],
					result[index],
				)
			}
		}
	})

	testCases := []struct {
		name string
		uri  string
	}{
		{
			name: "empty",
			uri:  "",
		},
		{
			name: "relative URI",
			uri:  "/auth/callback",
		},
		{
			name: "production HTTP",
			uri:  "http://portal.example.com/auth/callback",
		},
		{
			name: "loopback IP is not the documented exception",
			uri:  "http://127.0.0.1:5173/auth/callback",
		},
		{
			name: "localhost suffix attack",
			uri:  "http://localhost.example.com/auth/callback",
		},
		{
			name: "missing host",
			uri:  "https:///auth/callback",
		},
		{
			name: "fragment",
			uri:  "https://portal.example.com/auth/callback#fragment",
		},
		{
			name: "empty fragment",
			uri:  "https://portal.example.com/auth/callback#",
		},
		{
			name: "userinfo",
			uri:  "https://user@portal.example.com/auth/callback",
		},
		{
			name: "surrounding whitespace",
			uri:  " https://portal.example.com/auth/callback ",
		},
		{
			name: "unsupported scheme",
			uri:  "javascript:alert(1)",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ValidateRedirectURIs(
				[]string{testCase.uri},
			)
			if !errors.Is(err, ErrInvalidRedirectURI) {
				t.Fatalf(
					"expected ErrInvalidRedirectURI, got %v",
					err,
				)
			}
		})
	}

	t.Run("requires at least one URI", func(t *testing.T) {
		_, err := ValidateRedirectURIs(nil)
		if !errors.Is(err, ErrInvalidRedirectURI) {
			t.Fatalf(
				"expected ErrInvalidRedirectURI, got %v",
				err,
			)
		}
	})

	t.Run("rejects exact duplicates", func(t *testing.T) {
		_, err := ValidateRedirectURIs([]string{
			"https://portal.example.com/callback",
			"https://portal.example.com/callback",
		})
		if !errors.Is(err, ErrDuplicateRedirectURI) {
			t.Fatalf(
				"expected ErrDuplicateRedirectURI, got %v",
				err,
			)
		}
	})
}

func TestIsRedirectURIRegisteredUsesExactMatching(
	t *testing.T,
) {
	registered := []string{
		"https://portal.example.com/callback",
		"https://portal.example.com/callback?environment=dev",
	}

	testCases := []struct {
		name      string
		requested string
		expected  bool
	}{
		{
			name:      "exact path",
			requested: "https://portal.example.com/callback",
			expected:  true,
		},
		{
			name:      "exact query",
			requested: "https://portal.example.com/callback?environment=dev",
			expected:  true,
		},
		{
			name:      "trailing slash differs",
			requested: "https://portal.example.com/callback/",
			expected:  false,
		},
		{
			name:      "query differs",
			requested: "https://portal.example.com/callback?environment=prod",
			expected:  false,
		},
		{
			name:      "host case differs",
			requested: "https://PORTAL.example.com/callback",
			expected:  false,
		},
		{
			name:      "prefix is not enough",
			requested: "https://portal.example.com/callback/attacker",
			expected:  false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := IsRedirectURIRegistered(
				testCase.requested,
				registered,
			)

			if actual != testCase.expected {
				t.Fatalf(
					"expected %t, got %t",
					testCase.expected,
					actual,
				)
			}
		})
	}
}
