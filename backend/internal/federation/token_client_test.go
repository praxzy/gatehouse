package federation

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func federationTokenTestClient(
	t *testing.T,
) *TokenClient {
	t.Helper()

	client, err := NewTokenClient(
		NewProviderHTTPClient(
			ProviderNetworkPolicy{
				AllowHTTP:             true,
				AllowPrivateAddresses: true,
			},
		),
	)
	if err != nil {
		t.Fatalf(
			"create token client: %v",
			err,
		)
	}

	return client
}

func validTokenExchangeInput(
	tokenEndpoint string,
) TokenExchangeInput {
	artifacts, err :=
		GenerateAuthorizationArtifacts()
	if err != nil {
		panic(err)
	}

	return TokenExchangeInput{
		TokenEndpoint: tokenEndpoint,
		ClientID:      "gatehouse client",
		ClientSecret:  []byte("secret:value"),
		Code:          "authorization-code",
		RedirectURI:   "http://localhost:8080/api/v1/auth/federation/callback",
		PKCEVerifier:  artifacts.PKCEVerifier,
	}
}

func TestTokenClientExchangesAuthorizationCode(
	t *testing.T,
) {
	var requestCalls int

	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			requestCalls++

			if request.Method != http.MethodPost {
				t.Errorf(
					"unexpected method: %s",
					request.Method,
				)
			}

			if request.URL.Path != "/token" ||
				request.URL.RawQuery != "" {
				t.Errorf(
					"unexpected token URL: %s",
					request.URL,
				)
			}

			if request.Header.Get(
				"Content-Type",
			) !=
				"application/x-www-form-urlencoded" {
				t.Errorf(
					"unexpected content type: %q",
					request.Header.Get(
						"Content-Type",
					),
				)
			}

			username, password, ok :=
				request.BasicAuth()
			if !ok ||
				username != url.QueryEscape(
					"gatehouse client",
				) ||
				password != url.QueryEscape(
					"secret:value",
				) {
				t.Errorf(
					"unexpected client authentication",
				)
			}

			if err := request.ParseForm(); err != nil {
				t.Errorf(
					"parse token request: %v",
					err,
				)
			}

			expectedForm := map[string]string{
				"grant_type":   "authorization_code",
				"code":         "authorization-code",
				"redirect_uri": "http://localhost:8080/api/v1/auth/federation/callback",
			}

			for key, expected := range expectedForm {
				if request.Form.Get(key) != expected {
					t.Errorf(
						"unexpected %s: %q",
						key,
						request.Form.Get(key),
					)
				}
			}

			if _, err :=
				hashAuthorizationValue(
					request.Form.Get(
						"code_verifier",
					),
				); err != nil {
				t.Errorf(
					"invalid PKCE verifier: %v",
					err,
				)
			}

			writer.Header().Set(
				"Content-Type",
				"application/json",
			)

			_ = json.NewEncoder(writer).Encode(
				map[string]any{
					"access_token": "opaque-access-token",
					"token_type":   "Bearer",
					"expires_in":   int64(300),
					"id_token":     "header.payload.signature",
					"scope":        "openid",
				},
			)
		}),
	)
	defer server.Close()

	input := validTokenExchangeInput(
		server.URL + "/token",
	)

	result, err :=
		federationTokenTestClient(t).
			Exchange(t.Context(), input)
	if err != nil {
		t.Fatalf(
			"exchange authorization code: %v",
			err,
		)
	}

	if requestCalls != 1 ||
		result.AccessToken !=
			"opaque-access-token" ||
		result.TokenType != "Bearer" ||
		result.ExpiresIn != 300 ||
		result.IDToken !=
			"header.payload.signature" ||
		result.Scope != "openid" {
		t.Fatalf(
			"unexpected token result: %+v",
			result,
		)
	}
}

func TestTokenClientRejectsInvalidInput(
	t *testing.T,
) {
	serverCalls := 0

	server := httptest.NewServer(
		http.HandlerFunc(func(
			http.ResponseWriter,
			*http.Request,
		) {
			serverCalls++
		}),
	)
	defer server.Close()

	valid := validTokenExchangeInput(
		server.URL + "/token",
	)

	tests := []struct {
		name   string
		mutate func(*TokenExchangeInput)
	}{
		{
			name: "missing client ID",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.ClientID = ""
			},
		},
		{
			name: "missing client secret",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.ClientSecret = nil
			},
		},
		{
			name: "missing authorization code",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.Code = ""
			},
		},
		{
			name: "invalid verifier",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.PKCEVerifier =
					"not-a-verifier"
			},
		},
		{
			name: "unsafe redirect",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.RedirectURI =
					"http://gatehouse.example.com/callback"
			},
		},
		{
			name: "unsafe token endpoint",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.TokenEndpoint =
					"file:///token"
			},
		},
		{
			name: "control character in code",
			mutate: func(
				input *TokenExchangeInput,
			) {
				input.Code = "code\nvalue"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			input.ClientSecret = append(
				[]byte(nil),
				valid.ClientSecret...,
			)
			test.mutate(&input)

			_, err :=
				federationTokenTestClient(t).
					Exchange(
						t.Context(),
						input,
					)
			if !errors.Is(
				err,
				ErrInvalidTokenExchange,
			) {
				t.Fatalf(
					"expected invalid exchange, got %v",
					err,
				)
			}
		})
	}

	if serverCalls != 0 {
		t.Fatalf(
			"invalid inputs reached server %d times",
			serverCalls,
		)
	}
}

func TestTokenClientClassifiesProviderFailures(
	t *testing.T,
) {
	tests := []struct {
		name       string
		statusCode int
		expected   error
	}{
		{
			name:       "authorization rejected",
			statusCode: http.StatusBadRequest,
			expected:   ErrTokenExchangeRejected,
		},
		{
			name:       "invalid client",
			statusCode: http.StatusUnauthorized,
			expected:   ErrTokenExchangeRejected,
		},
		{
			name:       "provider failure",
			statusCode: http.StatusInternalServerError,
			expected:   ErrTokenEndpointUnavailable,
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
				}),
			)
			defer server.Close()

			input := validTokenExchangeInput(
				server.URL + "/token",
			)

			_, err :=
				federationTokenTestClient(t).
					Exchange(
						t.Context(),
						input,
					)
			if !errors.Is(
				err,
				test.expected,
			) {
				t.Fatalf(
					"expected %v, got %v",
					test.expected,
					err,
				)
			}
		})
	}
}

func TestTokenClientRejectsInvalidResponses(
	t *testing.T,
) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed JSON",
			body: `{`,
		},
		{
			name: "trailing JSON",
			body: `{
				"access_token":"access",
				"token_type":"Bearer",
				"id_token":"a.b.c"
			}{}`,
		},
		{
			name: "missing access token",
			body: `{
				"token_type":"Bearer",
				"id_token":"a.b.c"
			}`,
		},
		{
			name: "missing ID token",
			body: `{
				"access_token":"access",
				"token_type":"Bearer"
			}`,
		},
		{
			name: "unsupported token type",
			body: `{
				"access_token":"access",
				"token_type":"MAC",
				"id_token":"a.b.c"
			}`,
		},
		{
			name: "negative expiry",
			body: `{
				"access_token":"access",
				"token_type":"Bearer",
				"expires_in":-1,
				"id_token":"a.b.c"
			}`,
		},
		{
			name: "whitespace token",
			body: `{
				"access_token":" access ",
				"token_type":"Bearer",
				"id_token":"a.b.c"
			}`,
		},
		{
			name: "oversized response",
			body: strings.Repeat(
				"x",
				int(maxTokenResponseBytes)+1,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(
					writer http.ResponseWriter,
					_ *http.Request,
				) {
					writer.Header().Set(
						"Content-Type",
						"application/json",
					)
					_, _ = writer.Write(
						[]byte(test.body),
					)
				}),
			)
			defer server.Close()

			input := validTokenExchangeInput(
				server.URL + "/token",
			)

			_, err :=
				federationTokenTestClient(t).
					Exchange(
						t.Context(),
						input,
					)
			if !errors.Is(
				err,
				ErrInvalidTokenResponse,
			) {
				t.Fatalf(
					"expected invalid response, got %v",
					err,
				)
			}
		})
	}
}

func TestTokenClientRejectsInvalidConfiguration(
	t *testing.T,
) {
	if _, err := NewTokenClient(nil); !errors.Is(
		err,
		ErrInvalidTokenClient,
	) {
		t.Fatalf(
			"expected invalid client error, got %v",
			err,
		)
	}
}
