package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

type stubOIDCTokenService struct {
	result         oidc.TokenResult
	err            error
	called         bool
	values         url.Values
	authentication oidc.TokenClientAuthentication
}

func (service *stubOIDCTokenService) ExchangeAuthorizationCode(
	_ context.Context,
	values url.Values,
	authentication oidc.TokenClientAuthentication,
) (oidc.TokenResult, error) {
	service.called = true
	service.values = values
	service.authentication = authentication

	return service.result, service.err
}

func TestOIDCTokenEndpointReturnsNoStoreTokenResponse(
	t *testing.T,
) {
	service := &stubOIDCTokenService{
		result: oidc.TokenResult{
			AccessToken: "ghat_access-token",
			TokenType:   "Bearer",
			ExpiresIn:   900,
			IDToken:     "header.claims.signature",
			Scope:       "openid profile",
		},
	}

	request := newTokenEndpointRequest(
		validTokenEndpointForm(),
	)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		OIDCTokens: service,
	}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			response.Code,
		)
	}

	if response.Header().Get("Cache-Control") !=
		"no-store" {
		t.Fatalf(
			"unexpected cache control %q",
			response.Header().Get("Cache-Control"),
		)
	}

	if response.Header().Get("Pragma") != "no-cache" {
		t.Fatalf(
			"unexpected pragma %q",
			response.Header().Get("Pragma"),
		)
	}

	if !service.called {
		t.Fatal("token service was not called")
	}

	if service.authentication.Method !=
		oidc.TokenClientAuthenticationNone {
		t.Fatalf(
			"unexpected authentication method %q",
			service.authentication.Method,
		)
	}

	var result tokenResponse
	if err := json.NewDecoder(
		response.Body,
	).Decode(&result); err != nil {
		t.Fatalf(
			"decode token response: %v",
			err,
		)
	}

	if result.AccessToken !=
		service.result.AccessToken ||
		result.TokenType != "Bearer" ||
		result.ExpiresIn != 900 ||
		result.IDToken != service.result.IDToken ||
		result.Scope != service.result.Scope {
		t.Fatalf(
			"unexpected token response: %+v",
			result,
		)
	}
}

func TestOIDCTokenEndpointParsesBasicAuthentication(
	t *testing.T,
) {
	service := &stubOIDCTokenService{
		err: oidc.ErrInvalidTokenClient,
	}

	values := validTokenEndpointForm()
	values.Del("client_id")

	request := newTokenEndpointRequest(values)
	request.SetBasicAuth(
		"ghc_0123456789abcdefghijklmnopqrstuv",
		"ghs_confidential-secret",
	)

	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		OIDCTokens: service,
	}).ServeHTTP(response, request)

	if !service.called {
		t.Fatal("token service was not called")
	}

	if service.authentication.Method !=
		oidc.TokenClientAuthenticationBasic ||
		service.authentication.ClientID !=
			"ghc_0123456789abcdefghijklmnopqrstuv" ||
		service.authentication.ClientSecret !=
			"ghs_confidential-secret" {
		t.Fatalf(
			"unexpected client authentication: %+v",
			service.authentication,
		)
	}

	if response.Code != http.StatusUnauthorized {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusUnauthorized,
			response.Code,
		)
	}

	if response.Header().Get("WWW-Authenticate") == "" {
		t.Fatal(
			"invalid Basic client response omitted challenge",
		)
	}

	assertOAuthError(
		t,
		response,
		"invalid_client",
	)
}

func TestOIDCTokenEndpointRejectsInvalidTransport(
	t *testing.T,
) {
	tests := []struct {
		name    string
		request func() *http.Request
	}{
		{
			name: "query parameters",
			request: func() *http.Request {
				request := newTokenEndpointRequest(
					validTokenEndpointForm(),
				)
				request.URL.RawQuery = "code=query-code"
				return request
			},
		},
		{
			name: "wrong content type",
			request: func() *http.Request {
				request := httptest.NewRequest(
					http.MethodPost,
					"/oauth/token",
					strings.NewReader("{}"),
				)
				request.Header.Set(
					"Content-Type",
					"application/json",
				)
				return request
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &stubOIDCTokenService{}
			response := httptest.NewRecorder()

			NewRouter(Dependencies{
				OIDCTokens: service,
			}).ServeHTTP(
				response,
				test.request(),
			)

			if response.Code !=
				http.StatusBadRequest {
				t.Fatalf(
					"expected status %d, got %d",
					http.StatusBadRequest,
					response.Code,
				)
			}

			if service.called {
				t.Fatal(
					"invalid transport reached token service",
				)
			}

			assertOAuthError(
				t,
				response,
				"invalid_request",
			)
		})
	}
}

func TestOIDCTokenEndpointMapsInvalidGrant(
	t *testing.T,
) {
	service := &stubOIDCTokenService{
		err: oidc.ErrInvalidAuthorizationGrant,
	}

	request := newTokenEndpointRequest(
		validTokenEndpointForm(),
	)
	response := httptest.NewRecorder()

	NewRouter(Dependencies{
		OIDCTokens: service,
	}).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusBadRequest,
			response.Code,
		)
	}

	assertOAuthError(
		t,
		response,
		"invalid_grant",
	)
}

func newTokenEndpointRequest(
	values url.Values,
) *http.Request {
	request := httptest.NewRequest(
		http.MethodPost,
		"/oauth/token",
		strings.NewReader(values.Encode()),
	)

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)

	return request
}

func validTokenEndpointForm() url.Values {
	return url.Values{
		"grant_type": {
			"authorization_code",
		},
		"code": {
			"ghac_E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		},
		"redirect_uri": {
			"https://portal.example.test/oauth/callback",
		},
		"code_verifier": {
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		"client_id": {
			"ghc_0123456789abcdefghijklmnopqrstuv",
		},
	}
}

func assertOAuthError(
	t *testing.T,
	response *httptest.ResponseRecorder,
	expected string,
) {
	t.Helper()

	var result oauthErrorResponse
	if err := json.NewDecoder(
		response.Body,
	).Decode(&result); err != nil {
		t.Fatalf(
			"decode OAuth error response: %v",
			err,
		)
	}

	if result.Error != expected {
		t.Fatalf(
			"expected OAuth error %q, got %q",
			expected,
			result.Error,
		)
	}

	if response.Header().Get("Cache-Control") !=
		"no-store" {
		t.Fatal(
			"OAuth error response was cacheable",
		)
	}
}
