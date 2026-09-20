package federation

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func discoveryTestClient(
	t *testing.T,
) *DiscoveryClient {
	t.Helper()

	client, err := NewDiscoveryClient(
		NewProviderHTTPClient(
			ProviderNetworkPolicy{
				AllowHTTP:             true,
				AllowPrivateAddresses: true,
			},
		),
	)
	if err != nil {
		t.Fatalf("create discovery client: %v", err)
	}

	return client
}

func validDiscoveryDocument(
	issuer string,
) DiscoveryDocument {
	return DiscoveryDocument{
		Issuer: issuer,

		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSURI:               issuer + "/jwks",

		ResponseTypesSupported: []string{
			"code",
		},
		GrantTypesSupported: []string{
			"authorization_code",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
		},
		CodeChallengeMethodsSupported: []string{
			"S256",
		},
	}
}

func TestDiscoveryClientLoadsValidDocument(
	t *testing.T,
) {
	var server *httptest.Server

	server = httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			expectedPath :=
				"/tenant/.well-known/openid-configuration"

			if request.URL.Path != expectedPath {
				t.Errorf(
					"unexpected discovery path: %s",
					request.URL.Path,
				)
				http.NotFound(writer, request)
				return
			}

			if request.Header.Get("Accept") !=
				"application/json" {
				t.Errorf(
					"unexpected Accept header: %q",
					request.Header.Get("Accept"),
				)
			}

			document := validDiscoveryDocument(
				server.URL + "/tenant",
			)

			writer.Header().Set(
				"Content-Type",
				"application/json",
			)

			if err := json.NewEncoder(writer).Encode(
				document,
			); err != nil {
				t.Errorf(
					"encode discovery response: %v",
					err,
				)
			}
		}),
	)
	defer server.Close()

	issuer := server.URL + "/tenant"

	document, err := discoveryTestClient(t).Discover(
		t.Context(),
		issuer,
	)
	if err != nil {
		t.Fatalf("discover provider: %v", err)
	}

	if document.Issuer != issuer ||
		document.AuthorizationEndpoint !=
			issuer+"/authorize" ||
		document.TokenEndpoint != issuer+"/token" ||
		document.JWKSURI != issuer+"/jwks" {
		t.Fatalf(
			"unexpected discovery document: %+v",
			document,
		)
	}
}

func TestDiscoveryClientRejectsInvalidCapabilities(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*DiscoveryDocument)
	}{
		{
			name: "issuer mismatch",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.Issuer =
					"https://attacker.example.com"
			},
		},
		{
			name: "unsafe authorization endpoint",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.AuthorizationEndpoint =
					"/authorize"
			},
		},
		{
			name: "unsafe token endpoint",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.TokenEndpoint =
					"file:///token"
			},
		},
		{
			name: "unsafe JWKS endpoint",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.JWKSURI =
					"javascript:alert(1)"
			},
		},
		{
			name: "authorization code unsupported",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.ResponseTypesSupported =
					[]string{"id_token"}
			},
		},
		{
			name: "authorization code grant unsupported",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.GrantTypesSupported =
					[]string{"implicit"}
			},
		},
		{
			name: "openid scope unsupported",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.ScopesSupported =
					[]string{"profile"}
			},
		},
		{
			name: "RS256 unsupported",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.
					IDTokenSigningAlgValuesSupported =
					[]string{"HS256"}
			},
		},
		{
			name: "client secret basic unsupported",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.
					TokenEndpointAuthMethodsSupported =
					[]string{"private_key_jwt"}
			},
		},
		{
			name: "S256 unsupported",
			mutate: func(
				document *DiscoveryDocument,
			) {
				document.
					CodeChallengeMethodsSupported =
					[]string{"plain"}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var server *httptest.Server

			server = httptest.NewServer(
				http.HandlerFunc(func(
					writer http.ResponseWriter,
					_ *http.Request,
				) {
					issuer := server.URL
					document :=
						validDiscoveryDocument(
							issuer,
						)
					test.mutate(&document)

					_ = json.NewEncoder(
						writer,
					).Encode(document)
				}),
			)
			defer server.Close()

			_, err := discoveryTestClient(t).
				Discover(
					t.Context(),
					server.URL,
				)
			if !errors.Is(
				err,
				ErrInvalidDiscoveryDocument,
			) {
				t.Fatalf(
					"expected invalid discovery document, got %v",
					err,
				)
			}
		})
	}
}

func TestDiscoveryClientAppliesStandardDefaults(
	t *testing.T,
) {
	var server *httptest.Server

	server = httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			document := validDiscoveryDocument(
				server.URL,
			)

			document.GrantTypesSupported = nil
			document.
				TokenEndpointAuthMethodsSupported = nil

			_ = json.NewEncoder(writer).Encode(
				document,
			)
		}),
	)
	defer server.Close()

	if _, err := discoveryTestClient(t).Discover(
		t.Context(),
		server.URL,
	); err != nil {
		t.Fatalf(
			"standard discovery defaults rejected: %v",
			err,
		)
	}
}

func TestDiscoveryClientRejectsInvalidResponses(
	t *testing.T,
) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   error
	}{
		{
			name:       "non-success status",
			statusCode: http.StatusBadGateway,
			body:       `{}`,
			expected:   ErrDiscoveryUnavailable,
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			body:       `{`,
			expected:   ErrInvalidDiscoveryDocument,
		},
		{
			name:       "trailing JSON",
			statusCode: http.StatusOK,
			body:       `{} {}`,
			expected:   ErrInvalidDiscoveryDocument,
		},
		{
			name:       "oversized response",
			statusCode: http.StatusOK,
			body: strings.Repeat(
				"x",
				int(maxDiscoveryDocumentBytes)+1,
			),
			expected: ErrInvalidDiscoveryDocument,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(
					writer http.ResponseWriter,
					_ *http.Request,
				) {
					writer.WriteHeader(
						test.statusCode,
					)
					_, _ = writer.Write(
						[]byte(test.body),
					)
				}),
			)
			defer server.Close()

			_, err := discoveryTestClient(t).
				Discover(
					t.Context(),
					server.URL,
				)
			if !errors.Is(err, test.expected) {
				t.Fatalf(
					"expected %v, got %v",
					test.expected,
					err,
				)
			}
		})
	}
}

func TestDiscoveryClientRejectsUnsafeIssuer(
	t *testing.T,
) {
	client, err := NewDiscoveryClient(
		NewProviderHTTPClient(
			ProviderNetworkPolicy{},
		),
	)
	if err != nil {
		t.Fatalf(
			"create discovery client: %v",
			err,
		)
	}

	_, err = client.Discover(
		t.Context(),
		"http://127.0.0.1/provider",
	)
	if !errors.Is(
		err,
		ErrUnsafeProviderURL,
	) &&
		!errors.Is(
			err,
			ErrUnsafeProviderAddress,
		) {
		t.Fatalf(
			"expected unsafe issuer error, got %v",
			err,
		)
	}
}

func TestDiscoveryClientRejectsInvalidConfiguration(
	t *testing.T,
) {
	if _, err := NewDiscoveryClient(nil); !errors.Is(
		err,
		ErrInvalidDiscoveryClient,
	) {
		t.Fatalf(
			"expected invalid client error, got %v",
			err,
		)
	}
}
