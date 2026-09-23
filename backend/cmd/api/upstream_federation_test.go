package main

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
)

func clearUpstreamFederationEnvironment(
	t *testing.T,
) {
	t.Helper()

	names := []string{
		"UPSTREAM_OIDC_REDIRECT_URI",
		"UPSTREAM_OIDC_ENCRYPTION_KEY_ID",
		"UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64",
		"UPSTREAM_OIDC_ALLOW_HTTP",
		"UPSTREAM_OIDC_ALLOW_PRIVATE_ADDRESSES",
	}

	for _, name := range names {
		t.Setenv(name, "")
	}
}

func setValidUpstreamFederationEnvironment(
	t *testing.T,
) {
	t.Helper()

	clearUpstreamFederationEnvironment(t)

	t.Setenv(
		"UPSTREAM_OIDC_REDIRECT_URI",
		"http://localhost:5173/api/v1/auth/federation/callback",
	)
	t.Setenv(
		"UPSTREAM_OIDC_ENCRYPTION_KEY_ID",
		"test-federation-v1",
	)
	t.Setenv(
		"UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64",
		base64.StdEncoding.EncodeToString(
			bytes.Repeat([]byte{0x45}, 32),
		),
	)
	t.Setenv(
		"UPSTREAM_OIDC_ALLOW_HTTP",
		"false",
	)
	t.Setenv(
		"UPSTREAM_OIDC_ALLOW_PRIVATE_ADDRESSES",
		"false",
	)
}

func TestUpstreamFederationIsOptional(
	t *testing.T,
) {
	clearUpstreamFederationEnvironment(t)

	services, err :=
		upstreamFederationServicesFromEnvironment(
			&pgxpool.Pool{},
			&auth.Service{},
			audit.NewWriter(),
		)
	if err != nil {
		t.Fatalf(
			"configure disabled federation: %v",
			err,
		)
	}

	if services.authorization != nil ||
		services.callback != nil ||
		services.management != nil {
		t.Fatal(
			"expected federation services to remain disabled",
		)
	}
}

func TestUpstreamFederationConfigurationBuildsServices(
	t *testing.T,
) {
	setValidUpstreamFederationEnvironment(t)

	services, err :=
		upstreamFederationServicesFromEnvironment(
			&pgxpool.Pool{},
			&auth.Service{},
			audit.NewWriter(),
		)
	if err != nil {
		t.Fatalf(
			"configure upstream federation: %v",
			err,
		)
	}

	if services.authorization == nil ||
		services.callback == nil ||
		services.management == nil {
		t.Fatal(
			"expected configured federation services",
		)
	}
}

func TestUpstreamFederationRejectsInvalidConfiguration(
	t *testing.T,
) {
	testCases := []struct {
		name   string
		mutate func(*testing.T)
	}{
		{
			name: "missing encryption key ID",
			mutate: func(t *testing.T) {
				t.Setenv(
					"UPSTREAM_OIDC_ENCRYPTION_KEY_ID",
					"",
				)
			},
		},
		{
			name: "malformed encryption key",
			mutate: func(t *testing.T) {
				t.Setenv(
					"UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64",
					"not-valid-base64!",
				)
			},
		},
		{
			name: "wrong encryption key length",
			mutate: func(t *testing.T) {
				t.Setenv(
					"UPSTREAM_OIDC_ENCRYPTION_KEY_BASE64",
					base64.StdEncoding.EncodeToString(
						bytes.Repeat(
							[]byte{0x45},
							16,
						),
					),
				)
			},
		},
		{
			name: "invalid allow HTTP value",
			mutate: func(t *testing.T) {
				t.Setenv(
					"UPSTREAM_OIDC_ALLOW_HTTP",
					"sometimes",
				)
			},
		},
		{
			name: "invalid private address value",
			mutate: func(t *testing.T) {
				t.Setenv(
					"UPSTREAM_OIDC_ALLOW_PRIVATE_ADDRESSES",
					"sometimes",
				)
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			setValidUpstreamFederationEnvironment(t)
			test.mutate(t)

			_, err :=
				upstreamFederationServicesFromEnvironment(
					&pgxpool.Pool{},
					&auth.Service{},
					audit.NewWriter(),
				)
			if err == nil {
				t.Fatal(
					"expected invalid configuration error",
				)
			}
		})
	}
}
