package federation

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func federationJWKSTestClient(
	t *testing.T,
) *JWKSClient {
	t.Helper()

	client, err := NewJWKSClient(
		NewProviderHTTPClient(
			ProviderNetworkPolicy{
				AllowHTTP:             true,
				AllowPrivateAddresses: true,
			},
		),
	)
	if err != nil {
		t.Fatalf(
			"create JWKS client: %v",
			err,
		)
	}

	return client
}

func rsaPublicJWK(
	key *rsa.PublicKey,
	keyID string,
) map[string]any {
	exponent := big.NewInt(
		int64(key.E),
	).Bytes()

	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"kid": keyID,
		"alg": "RS256",
		"n": base64.RawURLEncoding.
			EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.
			EncodeToString(exponent),
	}
}

func generateJWKSTestKey(
	t *testing.T,
	bits int,
) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(
		rand.Reader,
		bits,
	)
	if err != nil {
		t.Fatalf(
			"generate RSA key: %v",
			err,
		)
	}

	return key
}

func TestJWKSClientLoadsExactRS256Key(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	keyID := "provider-key-v1"

	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if request.Method != http.MethodGet ||
				request.URL.Path != "/jwks" {
				t.Errorf(
					"unexpected JWKS request: %s %s",
					request.Method,
					request.URL,
				)
			}

			_ = json.NewEncoder(writer).Encode(
				map[string]any{
					"keys": []any{
						rsaPublicJWK(
							&privateKey.PublicKey,
							keyID,
						),
					},
				},
			)
		}),
	)
	defer server.Close()

	publicKey, err :=
		federationJWKSTestClient(t).
			GetRSASigningKey(
				t.Context(),
				server.URL+"/jwks",
				keyID,
			)
	if err != nil {
		t.Fatalf(
			"load signing key: %v",
			err,
		)
	}

	if publicKey.E != privateKey.E ||
		publicKey.N.Cmp(privateKey.N) != 0 {
		t.Fatal("loaded the wrong RSA key")
	}
}

func TestJWKSClientRejectsInvalidMatchingKey(
	t *testing.T,
) {
	validKey := generateJWKSTestKey(
		t,
		2048,
	)

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "wrong key type",
			mutate: func(key map[string]any) {
				key["kty"] = "EC"
			},
		},
		{
			name: "encryption use",
			mutate: func(key map[string]any) {
				key["use"] = "enc"
			},
		},
		{
			name: "wrong algorithm",
			mutate: func(key map[string]any) {
				key["alg"] = "RS512"
			},
		},
		{
			name: "invalid modulus",
			mutate: func(key map[string]any) {
				key["n"] = "not-base64!"
			},
		},
		{
			name: "weak modulus",
			mutate: func(key map[string]any) {
				key["n"] =
					base64.RawURLEncoding.
						EncodeToString(
							[]byte{3},
						)
			},
		},
		{
			name: "invalid exponent",
			mutate: func(key map[string]any) {
				key["e"] =
					base64.RawURLEncoding.
						EncodeToString(
							[]byte{2},
						)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := rsaPublicJWK(
				&validKey.PublicKey,
				"matching-key",
			)
			test.mutate(key)

			server := httptest.NewServer(
				http.HandlerFunc(func(
					writer http.ResponseWriter,
					_ *http.Request,
				) {
					_ = json.NewEncoder(
						writer,
					).Encode(
						map[string]any{
							"keys": []any{
								key,
							},
						},
					)
				}),
			)
			defer server.Close()

			_, err :=
				federationJWKSTestClient(t).
					GetRSASigningKey(
						t.Context(),
						server.URL,
						"matching-key",
					)
			if !errors.Is(
				err,
				ErrInvalidJWKS,
			) {
				t.Fatalf(
					"expected invalid JWKS, got %v",
					err,
				)
			}
		})
	}
}

func TestJWKSClientRejectsDuplicateKeyID(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	key := rsaPublicJWK(
		&privateKey.PublicKey,
		"duplicate-key",
	)

	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			_ = json.NewEncoder(writer).Encode(
				map[string]any{
					"keys": []any{key, key},
				},
			)
		}),
	)
	defer server.Close()

	_, err := federationJWKSTestClient(t).
		GetRSASigningKey(
			t.Context(),
			server.URL,
			"duplicate-key",
		)
	if !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf(
			"expected duplicate rejection, got %v",
			err,
		)
	}
}

func TestJWKSClientRejectsDuplicateJSONMembers(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	modulus := base64.RawURLEncoding.
		EncodeToString(
			privateKey.N.Bytes(),
		)

	body := `{"keys":[{` +
		`"kty":"RSA",` +
		`"kid":"duplicate",` +
		`"kid":"duplicate",` +
		`"alg":"RS256",` +
		`"n":"` + modulus + `",` +
		`"e":"AQAB"` +
		`}]}`

	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			_, _ = writer.Write(
				[]byte(body),
			)
		}),
	)
	defer server.Close()

	_, err := federationJWKSTestClient(t).
		GetRSASigningKey(
			t.Context(),
			server.URL,
			"duplicate",
		)
	if !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf(
			"expected duplicate member rejection, got %v",
			err,
		)
	}
}

func TestJWKSClientRejectsUnknownKeyID(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)

	server := httptest.NewServer(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			_ = json.NewEncoder(writer).Encode(
				map[string]any{
					"keys": []any{
						rsaPublicJWK(
							&privateKey.PublicKey,
							"different-key",
						),
					},
				},
			)
		}),
	)
	defer server.Close()

	_, err := federationJWKSTestClient(t).
		GetRSASigningKey(
			t.Context(),
			server.URL,
			"missing-key",
		)
	if !errors.Is(
		err,
		ErrSigningKeyUnavailable,
	) {
		t.Fatalf(
			"expected missing key error, got %v",
			err,
		)
	}
}

func TestJWKSClientRejectsInvalidResponses(
	t *testing.T,
) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		expected   error
	}{
		{
			name:       "provider unavailable",
			statusCode: http.StatusBadGateway,
			body:       `{}`,
			expected:   ErrJWKSUnavailable,
		},
		{
			name:       "malformed JSON",
			statusCode: http.StatusOK,
			body:       `{`,
			expected:   ErrInvalidJWKS,
		},
		{
			name:       "missing keys",
			statusCode: http.StatusOK,
			body:       `{}`,
			expected:   ErrInvalidJWKS,
		},
		{
			name:       "oversized response",
			statusCode: http.StatusOK,
			body: strings.Repeat(
				"x",
				int(maxJWKSBytes)+1,
			),
			expected: ErrInvalidJWKS,
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

			_, err :=
				federationJWKSTestClient(t).
					GetRSASigningKey(
						t.Context(),
						server.URL,
						"key",
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

func TestJWKSClientRejectsInvalidConfiguration(
	t *testing.T,
) {
	if _, err := NewJWKSClient(nil); !errors.Is(
		err,
		ErrInvalidJWKSClient,
	) {
		t.Fatalf(
			"expected invalid client error, got %v",
			err,
		)
	}
}
