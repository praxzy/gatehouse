package integration_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/google/uuid"

	"github.com/praxzy/gatehouse/backend/internal/application"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

const (
	testTokenClientSecret = "ghs_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"

	testTokenCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	testSecondaryTokenClientID = "ghc_abcdefghijklmnopqrstuvwxyzABCDEF"

	testSecondaryTokenClientSecret = "ghs_secondary-client-secret-0123456789"
)

type tokenEndpointResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

func TestAuthorizationCodeTokenExchange(
	t *testing.T,
) {
	ctx := context.Background()

	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Token Company",
			TenantSlug:  "token-company",
			Email:       "owner@token.test",
			DisplayName: "Token Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf(
			"register token tenant: %v",
			err,
		)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	clientSecretHash := application.HashClientSecret(
		testTokenClientSecret,
	)

	var applicationID pgtype.UUID
	if err := pool.QueryRow(
		ctx,
		`
			INSERT INTO applications (
				tenant_id,
				name,
				client_id,
				client_type,
				client_secret_hash,
				client_secret_created_at,
				status,
				access_mode
			)
			VALUES (
				$1,
				'Token Portal',
				$2,
				'confidential',
				$3,
				now(),
				'active',
				'all_active_members'
			)
			RETURNING id
		`,
		registration.TenantID,
		testAuthorizationClientID,
		clientSecretHash,
	).Scan(&applicationID); err != nil {
		t.Fatalf(
			"create token application: %v",
			err,
		)
	}

	if _, err := pool.Exec(
		ctx,
		`
			INSERT INTO redirect_uris (
				tenant_id,
				application_id,
				uri
			)
			VALUES ($1, $2, $3)
		`,
		registration.TenantID,
		applicationID,
		testAuthorizationRedirect,
	); err != nil {
		t.Fatalf(
			"create token redirect URI: %v",
			err,
		)
	}

	secondarySecretHash := application.HashClientSecret(
		testSecondaryTokenClientSecret,
	)

	if _, err := pool.Exec(
		ctx,
		`
			INSERT INTO applications (
				tenant_id,
				name,
				client_id,
				client_type,
				client_secret_hash,
				client_secret_created_at,
				status,
				access_mode
			)
			VALUES (
				$1,
				'Secondary Token Client',
				$2,
				'confidential',
				$3,
				now(),
				'active',
				'all_active_members'
			)
		`,
		registration.TenantID,
		testSecondaryTokenClientID,
		secondarySecretHash,
	); err != nil {
		t.Fatalf(
			"create secondary token client: %v",
			err,
		)
	}

	provider := newTokenTestProvider(t)

	authorization, err :=
		oidc.NewAuthorizationService(pool)
	if err != nil {
		t.Fatalf(
			"create authorization service: %v",
			err,
		)
	}

	tokens, err := oidc.NewTokenService(
		pool,
		provider,
	)
	if err != nil {
		t.Fatalf(
			"create token service: %v",
			err,
		)
	}

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication:    authentication,
			OIDCAuthorization: authorization,
			OIDCTokens:        tokens,
			SessionCookie: httpapi.NewSessionCookie(
				true,
			),
		},
	)

	sessionCookie := loginLifecycleUser(
		t,
		router,
		"token-company",
		"owner@token.test",
		"correct horse battery staple",
	)

	code := issueTokenTestAuthorizationCode(
		t,
		router,
		sessionCookie,
		"token-success-state-0123456789",
	)

	response := performTokenExchange(
		router,
		tokenExchangeValues(code),
		testAuthorizationClientID,
		testTokenClientSecret,
	)

	body := requireResponseStatus(
		t,
		response,
		http.StatusOK,
	)

	var tokenResult tokenEndpointResponse
	if err := json.Unmarshal(
		body,
		&tokenResult,
	); err != nil {
		t.Fatalf(
			"decode token response: %v",
			err,
		)
	}

	if len(tokenResult.AccessToken) != 48 ||
		tokenResult.AccessToken[:5] != "ghat_" {
		t.Fatalf(
			"unexpected access token %q",
			tokenResult.AccessToken,
		)
	}

	if tokenResult.TokenType != "Bearer" {
		t.Fatalf(
			"unexpected token type %q",
			tokenResult.TokenType,
		)
	}

	if tokenResult.ExpiresIn < 898 ||
		tokenResult.ExpiresIn > 900 {
		t.Fatalf(
			"unexpected expires_in %d",
			tokenResult.ExpiresIn,
		)
	}

	verifyTokenTestIDToken(
		t,
		provider,
		tokenResult.IDToken,
		registration.UserID,
		"nonce-token-success-state-0123456789",
	)

	if tokenResult.Scope !=
		"openid profile email" {
		t.Fatalf(
			"unexpected granted scope %q",
			tokenResult.Scope,
		)
	}

	if response.Header.Get("Cache-Control") !=
		"no-store" ||
		response.Header.Get("Pragma") !=
			"no-cache" {
		t.Fatal(
			"token response was cacheable",
		)
	}

	accessTokenHash := sha256.Sum256(
		[]byte(tokenResult.AccessToken),
	)

	var storedAccessTokens int
	if err := pool.QueryRow(
		ctx,
		`
			SELECT count(*)
			FROM access_tokens
			WHERE token_hash = $1
			  AND tenant_id = $2
			  AND application_id = $3
			  AND user_id = $4
		`,
		accessTokenHash[:],
		registration.TenantID,
		applicationID,
		registration.UserID,
	).Scan(&storedAccessTokens); err != nil {
		t.Fatalf(
			"count stored access token: %v",
			err,
		)
	}

	if storedAccessTokens != 1 {
		t.Fatalf(
			"expected one stored access token, got %d",
			storedAccessTokens,
		)
	}

	reusedResponse := performTokenExchange(
		router,
		tokenExchangeValues(code),
		testAuthorizationClientID,
		testTokenClientSecret,
	)

	requireOAuthTokenError(
		t,
		reusedResponse,
		http.StatusBadRequest,
		"invalid_grant",
	)

	t.Run("wrong client cannot redeem code", func(t *testing.T) {
		code := issueTokenTestAuthorizationCode(
			t,
			router,
			sessionCookie,
			"token-wrong-client-state-0123456789",
		)

		response := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testSecondaryTokenClientID,
			testSecondaryTokenClientSecret,
		)

		requireOAuthTokenError(
			t,
			response,
			http.StatusBadRequest,
			"invalid_grant",
		)

		validResponse := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireResponseStatus(
			t,
			validResponse,
			http.StatusOK,
		)
	})

	t.Run("wrong client secret is rejected", func(t *testing.T) {
		code := issueTokenTestAuthorizationCode(
			t,
			router,
			sessionCookie,
			"token-wrong-secret-state-0123456789",
		)

		response := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testAuthorizationClientID,
			"ghs_wrong-secret",
		)

		requireOAuthTokenError(
			t,
			response,
			http.StatusUnauthorized,
			"invalid_client",
		)

		if response.Header.Get("WWW-Authenticate") == "" {
			t.Fatal(
				"invalid confidential client omitted authentication challenge",
			)
		}

		validResponse := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireResponseStatus(
			t,
			validResponse,
			http.StatusOK,
		)
	})

	t.Run("wrong PKCE verifier does not consume code", func(t *testing.T) {
		code := issueTokenTestAuthorizationCode(
			t,
			router,
			sessionCookie,
			"token-wrong-verifier-state-0123456789",
		)

		values := tokenExchangeValues(code)
		values.Set(
			"code_verifier",
			strings.Repeat("a", 43),
		)

		response := performTokenExchange(
			router,
			values,
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireOAuthTokenError(
			t,
			response,
			http.StatusBadRequest,
			"invalid_grant",
		)

		validResponse := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireResponseStatus(
			t,
			validResponse,
			http.StatusOK,
		)
	})

	t.Run("wrong redirect URI does not consume code", func(t *testing.T) {
		code := issueTokenTestAuthorizationCode(
			t,
			router,
			sessionCookie,
			"token-wrong-redirect-state-0123456789",
		)

		values := tokenExchangeValues(code)
		values.Set(
			"redirect_uri",
			"https://attacker.example.test/callback",
		)

		response := performTokenExchange(
			router,
			values,
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireOAuthTokenError(
			t,
			response,
			http.StatusBadRequest,
			"invalid_grant",
		)

		validResponse := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireResponseStatus(
			t,
			validResponse,
			http.StatusOK,
		)
	})

	t.Run("expired code is rejected", func(t *testing.T) {
		code := issueTokenTestAuthorizationCode(
			t,
			router,
			sessionCookie,
			"token-expired-code-state-0123456789",
		)

		codeHash := sha256.Sum256([]byte(code))

		if _, err := pool.Exec(
			ctx,
			`
				UPDATE authorization_codes
				SET
					authentication_time =
						now() - interval '3 minutes',
					created_at =
						now() - interval '2 minutes',
					expires_at =
						now() - interval '1 minute'
				WHERE code_hash = $1
			`,
			codeHash[:],
		); err != nil {
			t.Fatalf(
				"expire authorization code: %v",
				err,
			)
		}

		response := performTokenExchange(
			router,
			tokenExchangeValues(code),
			testAuthorizationClientID,
			testTokenClientSecret,
		)

		requireOAuthTokenError(
			t,
			response,
			http.StatusBadRequest,
			"invalid_grant",
		)
	})

	t.Run("concurrent redemption succeeds exactly once", func(t *testing.T) {
		code := issueTokenTestAuthorizationCode(
			t,
			router,
			sessionCookie,
			"token-concurrent-state-0123456789",
		)

		const attempts = 8

		type exchangeOutcome struct {
			status int
			code   string
		}

		start := make(chan struct{})
		outcomes := make(
			chan exchangeOutcome,
			attempts,
		)

		for range attempts {
			go func() {
				<-start

				response := performTokenExchange(
					router,
					tokenExchangeValues(code),
					testAuthorizationClientID,
					testTokenClientSecret,
				)

				outcome := exchangeOutcome{
					status: response.StatusCode,
				}

				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()

				if err != nil {
					outcome.code = "read_error"
				} else if response.StatusCode != http.StatusOK {
					var result tokenEndpointResponse
					if json.Unmarshal(body, &result) == nil {
						outcome.code = result.Error
					}
				}

				outcomes <- outcome
			}()
		}

		close(start)

		successes := 0
		invalidGrants := 0

		for range attempts {
			outcome := <-outcomes

			switch {
			case outcome.status == http.StatusOK:
				successes++

			case outcome.status == http.StatusBadRequest &&
				outcome.code == "invalid_grant":
				invalidGrants++

			default:
				t.Fatalf(
					"unexpected concurrent outcome: %+v",
					outcome,
				)
			}
		}

		if successes != 1 {
			t.Fatalf(
				"expected one successful redemption, got %d",
				successes,
			)
		}

		if invalidGrants != attempts-1 {
			t.Fatalf(
				"expected %d invalid grants, got %d",
				attempts-1,
				invalidGrants,
			)
		}

		codeHash := sha256.Sum256([]byte(code))

		var issuedTokens int
		if err := pool.QueryRow(
			ctx,
			`
				SELECT count(*)
				FROM access_tokens
				WHERE authorization_code_hash = $1
			`,
			codeHash[:],
		).Scan(&issuedTokens); err != nil {
			t.Fatalf(
				"count concurrently issued tokens: %v",
				err,
			)
		}

		if issuedTokens != 1 {
			t.Fatalf(
				"expected one persisted token, got %d",
				issuedTokens,
			)
		}
	})
}

func issueTokenTestAuthorizationCode(
	t *testing.T,
	router http.Handler,
	sessionCookie *http.Cookie,
	state string,
) string {
	t.Helper()

	response := performRequest(
		t,
		router,
		http.MethodGet,
		authorizationRequestTarget(
			map[string]string{
				"state": state,
				"nonce": "nonce-" + state,
			},
		),
		nil,
		sessionCookie,
	)

	return requireAuthorizationGrant(
		t,
		response,
		state,
	)
}

func tokenExchangeValues(
	code string,
) url.Values {
	return url.Values{
		"grant_type": {
			"authorization_code",
		},
		"code": {
			code,
		},
		"redirect_uri": {
			testAuthorizationRedirect,
		},
		"code_verifier": {
			testTokenCodeVerifier,
		},
	}
}

func performTokenExchange(
	router http.Handler,
	values url.Values,
	clientID string,
	clientSecret string,
) *http.Response {
	request := httptest.NewRequest(
		http.MethodPost,
		"/oauth/token",
		strings.NewReader(values.Encode()),
	)
	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.SetBasicAuth(
		clientID,
		clientSecret,
	)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	return recorder.Result()
}

func requireOAuthTokenError(
	t *testing.T,
	response *http.Response,
	expectedStatus int,
	expectedCode string,
) {
	t.Helper()

	body := requireResponseStatus(
		t,
		response,
		expectedStatus,
	)

	var result tokenEndpointResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf(
			"decode OAuth token error: %v",
			err,
		)
	}

	if result.Error != expectedCode {
		t.Fatalf(
			"expected OAuth error %q, got %q",
			expectedCode,
			result.Error,
		)
	}

	if response.Header.Get("Cache-Control") !=
		"no-store" {
		t.Fatal(
			"OAuth token error was cacheable",
		)
	}
}

func newTokenTestProvider(
	t *testing.T,
) *oidc.Provider {
	t.Helper()

	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Fatalf(
			"generate token signing key: %v",
			err,
		)
	}

	encodedPrivateKey, err :=
		x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf(
			"encode token signing key: %v",
			err,
		)
	}

	signingKey, err := oidc.ParseRSAPrivateKeyPEM(
		"token-test-key",
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: encodedPrivateKey,
			},
		),
	)
	if err != nil {
		t.Fatalf(
			"parse token signing key: %v",
			err,
		)
	}

	config, err := oidc.NewProviderConfig(
		"https://identity.example.test",
	)
	if err != nil {
		t.Fatalf(
			"create token provider config: %v",
			err,
		)
	}

	provider, err := oidc.NewProvider(
		config,
		signingKey,
	)
	if err != nil {
		t.Fatalf(
			"create token provider: %v",
			err,
		)
	}

	return provider
}

func verifyTokenTestIDToken(
	t *testing.T,
	provider *oidc.Provider,
	rawToken string,
	expectedUserID pgtype.UUID,
	expectedNonce string,
) {
	t.Helper()

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatal(
			"ID token was not a compact signed JWT",
		)
	}

	headerBytes, err :=
		base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf(
			"decode ID token header: %v",
			err,
		)
	}

	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}

	if err := json.Unmarshal(
		headerBytes,
		&header,
	); err != nil {
		t.Fatalf(
			"decode ID token header JSON: %v",
			err,
		)
	}

	if header.Algorithm != "RS256" ||
		header.Type != "JWT" ||
		header.KeyID != "token-test-key" {
		t.Fatalf(
			"unexpected ID token header: %+v",
			header,
		)
	}

	claimsBytes, err :=
		base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf(
			"decode ID token claims: %v",
			err,
		)
	}

	var claims oidc.IDTokenClaims
	if err := json.Unmarshal(
		claimsBytes,
		&claims,
	); err != nil {
		t.Fatalf(
			"decode ID token claims JSON: %v",
			err,
		)
	}

	expectedSubject := uuid.UUID(
		expectedUserID.Bytes,
	).String()

	if claims.Issuer !=
		"https://identity.example.test" ||
		claims.Subject != expectedSubject ||
		claims.Audience != testAuthorizationClientID ||
		claims.Nonce != expectedNonce ||
		claims.Name != "Token Owner" ||
		claims.Email != "owner@token.test" ||
		!claims.EmailVerified ||
		!slices.Contains(claims.Roles, "Owner") {
		t.Fatalf(
			"unexpected ID token claims: %+v",
			claims,
		)
	}

	if claims.IssuedAt <= 0 ||
		claims.ExpiresAt <= claims.IssuedAt ||
		claims.AuthenticationTime <= 0 ||
		claims.AuthenticationTime > claims.IssuedAt {
		t.Fatalf(
			"invalid ID token timestamps: %+v",
			claims,
		)
	}

	keySet := provider.JSONWebKeySet()
	if len(keySet.Keys) != 1 {
		t.Fatalf(
			"expected one published signing key, got %d",
			len(keySet.Keys),
		)
	}

	jwk := keySet.Keys[0]
	if jwk.KeyID != header.KeyID ||
		jwk.Algorithm != "RS256" ||
		jwk.KeyType != "RSA" {
		t.Fatalf(
			"published JWK did not match token header: %+v",
			jwk,
		)
	}

	modulusBytes, err :=
		base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil {
		t.Fatalf(
			"decode JWK modulus: %v",
			err,
		)
	}

	exponentBytes, err :=
		base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil {
		t.Fatalf(
			"decode JWK exponent: %v",
			err,
		)
	}

	exponent := new(big.Int).SetBytes(
		exponentBytes,
	)
	if !exponent.IsInt64() {
		t.Fatal(
			"JWK exponent did not fit into int64",
		)
	}

	signature, err :=
		base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf(
			"decode ID token signature: %v",
			err,
		)
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent.Int64()),
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256(
		[]byte(signingInput),
	)

	if err := rsa.VerifyPKCS1v15(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
	); err != nil {
		t.Fatalf(
			"verify ID token with published JWK: %v",
			err,
		)
	}
}
