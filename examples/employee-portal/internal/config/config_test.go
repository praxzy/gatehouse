package config

import (
	"errors"
	"testing"
)

func TestLoad(t *testing.T) {
	values := map[string]string{
		"EMPLOYEE_PORTAL_HTTP_ADDR":          ":8090",
		"EMPLOYEE_PORTAL_OIDC_ISSUER":        "http://localhost:5173",
		"EMPLOYEE_PORTAL_OIDC_CLIENT_ID":     "ghc_employee_portal",
		"EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET": "ghs_employee_portal_secret",
		"EMPLOYEE_PORTAL_OIDC_REDIRECT_URI":  "http://localhost:8090/oauth/callback",
		"EMPLOYEE_PORTAL_COOKIE_SECURE":      "false",
	}

	configuration, err := Load(func(key string) string {
		return values[key]
	})
	if err != nil {
		t.Fatalf("load configuration: %v", err)
	}

	if configuration.HTTPAddress != ":8090" ||
		configuration.Issuer != "http://localhost:5173" ||
		configuration.ClientID != "ghc_employee_portal" ||
		configuration.ClientSecret != "ghs_employee_portal_secret" ||
		configuration.RedirectURI !=
			"http://localhost:8090/oauth/callback" ||
		configuration.SessionCookieSecure {
		t.Fatalf("unexpected configuration: %#v", configuration)
	}
}

func TestLoadRejectsUnsafeOrIncompleteConfiguration(
	t *testing.T,
) {
	tests := map[string]map[string]string{
		"missing client secret": {
			"EMPLOYEE_PORTAL_HTTP_ADDR":         ":8090",
			"EMPLOYEE_PORTAL_OIDC_ISSUER":       "https://id.example.test",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_ID":    "client",
			"EMPLOYEE_PORTAL_OIDC_REDIRECT_URI": "https://portal.example.test/oauth/callback",
			"EMPLOYEE_PORTAL_COOKIE_SECURE":     "true",
		},
		"remote HTTP issuer": {
			"EMPLOYEE_PORTAL_HTTP_ADDR":          ":8090",
			"EMPLOYEE_PORTAL_OIDC_ISSUER":        "http://id.example.test",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_ID":     "client",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET": "secret",
			"EMPLOYEE_PORTAL_OIDC_REDIRECT_URI":  "https://portal.example.test/oauth/callback",
			"EMPLOYEE_PORTAL_COOKIE_SECURE":      "true",
		},
		"issuer with path": {
			"EMPLOYEE_PORTAL_HTTP_ADDR":          ":8090",
			"EMPLOYEE_PORTAL_OIDC_ISSUER":        "https://id.example.test/issuer",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_ID":     "client",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET": "secret",
			"EMPLOYEE_PORTAL_OIDC_REDIRECT_URI":  "https://portal.example.test/oauth/callback",
			"EMPLOYEE_PORTAL_COOKIE_SECURE":      "true",
		},
		"invalid cookie setting": {
			"EMPLOYEE_PORTAL_HTTP_ADDR":          ":8090",
			"EMPLOYEE_PORTAL_OIDC_ISSUER":        "https://id.example.test",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_ID":     "client",
			"EMPLOYEE_PORTAL_OIDC_CLIENT_SECRET": "secret",
			"EMPLOYEE_PORTAL_OIDC_REDIRECT_URI":  "https://portal.example.test/oauth/callback",
			"EMPLOYEE_PORTAL_COOKIE_SECURE":      "sometimes",
		},
	}

	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Load(func(key string) string {
				return values[key]
			})
			if !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf(
					"expected ErrInvalidConfiguration, got %v",
					err,
				)
			}
		})
	}
}
