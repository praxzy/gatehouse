package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

const (
	testAuthorizationClientID = "ghc_0123456789abcdefghijklmnopqrstuv"
	testAuthorizationRedirect = "https://portal.example.test/oauth/callback?source=gatehouse"
	testAuthorizationState    = "state-0123456789abcdef"
	testAuthorizationNonce    = "nonce-0123456789abcdef"
	testAuthorizationPKCE     = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestSecureAuthorizationRequestLifecycle(
	t *testing.T,
) {
	ctx := context.Background()

	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Authorization Company",
			TenantSlug:  "authorization-company",
			Email:       "owner@authorization.test",
			DisplayName: "Authorization Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register authorization tenant: %v", err)
	}

	var applicationID pgtype.UUID
	if err := pool.QueryRow(
		ctx,
		`
			INSERT INTO applications (
				tenant_id,
				name,
				client_id,
				client_type,
				status,
				access_mode
			)
			VALUES ($1, $2, $3, 'public', 'active', 'all_active_members')
			RETURNING id
		`,
		registration.TenantID,
		"Authorization Portal",
		testAuthorizationClientID,
	).Scan(&applicationID); err != nil {
		t.Fatalf("create authorization application: %v", err)
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
		t.Fatalf("create authorization redirect URI: %v", err)
	}

	authorization, err :=
		oidc.NewAuthorizationService(pool)
	if err != nil {
		t.Fatalf(
			"create authorization service: %v",
			err,
		)
	}

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			OIDCAuthorization: authorization,
		},
	)

	t.Run(
		"attacker redirect URI is never trusted",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"redirect_uri": "https://attacker.example/callback",
					},
				),
				nil,
				nil,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusBadRequest,
			)

			if location := response.Header.Get("Location"); location != "" {
				t.Fatalf(
					"untrusted request received redirect %q",
					location,
				)
			}

			assertAuthorizationTransactionCount(
				t,
				ctx,
				pool,
				0,
			)
		},
	)

	t.Run(
		"missing PKCE redirects only to trusted URI",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"code_challenge":        "",
						"code_challenge_method": "",
					},
				),
				nil,
				nil,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusFound,
			)

			assertAuthorizationErrorRedirect(
				t,
				response,
				"invalid_request",
				testAuthorizationState,
			)

			assertAuthorizationTransactionCount(
				t,
				ctx,
				pool,
				0,
			)
		},
	)

	t.Run(
		"unsupported response type is rejected",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"response_type": "token",
					},
				),
				nil,
				nil,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusFound,
			)

			assertAuthorizationErrorRedirect(
				t,
				response,
				"unsupported_response_type",
				testAuthorizationState,
			)

			assertAuthorizationTransactionCount(
				t,
				ctx,
				pool,
				0,
			)
		},
	)

	var transactionID pgtype.UUID

	t.Run(
		"valid request persists short-lived transaction",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(nil),
				nil,
				nil,
			)

			body := requireResponseStatus(
				t,
				response,
				http.StatusOK,
			)

			var result struct {
				TransactionID string `json:"transaction_id"`
				Application   struct {
					Name     string `json:"name"`
					ClientID string `json:"client_id"`
				} `json:"application"`
				RequestedScope []string `json:"requested_scope"`
			}

			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatalf(
					"decode authorization response: %v",
					err,
				)
			}

			parsedID, err := uuid.Parse(
				result.TransactionID,
			)
			if err != nil {
				t.Fatalf(
					"parse transaction ID: %v",
					err,
				)
			}

			transactionID = pgtype.UUID{
				Bytes: [16]byte(parsedID),
				Valid: true,
			}

			if result.Application.Name !=
				"Authorization Portal" {
				t.Fatalf(
					"unexpected application name %q",
					result.Application.Name,
				)
			}

			if result.Application.ClientID !=
				testAuthorizationClientID {
				t.Fatalf(
					"unexpected client ID %q",
					result.Application.ClientID,
				)
			}

			expectedStateHash := sha256.Sum256(
				[]byte(testAuthorizationState),
			)

			var (
				storedStateHash []byte
				storedNonce     string
				storedChallenge string
				lifetime        time.Duration
			)

			if err := pool.QueryRow(
				ctx,
				`
					SELECT
						state_hash,
						nonce,
						code_challenge,
						expires_at - created_at
					FROM authorization_transactions
					WHERE id = $1
				`,
				transactionID,
			).Scan(
				&storedStateHash,
				&storedNonce,
				&storedChallenge,
				&lifetime,
			); err != nil {
				t.Fatalf(
					"load authorization transaction: %v",
					err,
				)
			}

			if !bytes.Equal(
				storedStateHash,
				expectedStateHash[:],
			) {
				t.Fatal(
					"authorization state was not stored as its SHA-256 hash",
				)
			}

			if storedNonce != testAuthorizationNonce {
				t.Fatal("authorization nonce was not preserved")
			}

			if storedChallenge != testAuthorizationPKCE {
				t.Fatal("PKCE challenge was not preserved")
			}

			if lifetime <= 0 ||
				lifetime > 5*time.Minute {
				t.Fatalf(
					"unexpected transaction lifetime %s",
					lifetime,
				)
			}
		},
	)

	t.Run(
		"expired transaction cannot resume",
		func(t *testing.T) {
			if _, err := pool.Exec(
				ctx,
				`
					UPDATE authorization_transactions
					SET
						created_at = now() - interval '6 minutes',
						expires_at = now() - interval '1 minute'
					WHERE id = $1
				`,
				transactionID,
			); err != nil {
				t.Fatalf(
					"expire authorization transaction: %v",
					err,
				)
			}

			_, err := authorization.LoadAuthorization(
				ctx,
				transactionID,
				testAuthorizationState,
			)
			if !errors.Is(
				err,
				oidc.ErrAuthorizationTransactionExpired,
			) {
				t.Fatalf(
					"expected expired transaction error, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"disabled client is rejected without redirect",
		func(t *testing.T) {
			if _, err := pool.Exec(
				ctx,
				`
					UPDATE applications
					SET
						status = 'disabled',
						updated_at = now()
					WHERE id = $1
				`,
				applicationID,
			); err != nil {
				t.Fatalf("disable application: %v", err)
			}

			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"state": "different-state-0123456789",
						"nonce": "different-nonce-0123456789",
					},
				),
				nil,
				nil,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusBadRequest,
			)

			if location := response.Header.Get("Location"); location != "" {
				t.Fatalf(
					"disabled client received redirect %q",
					location,
				)
			}
		},
	)
}

func authorizationRequestTarget(
	overrides map[string]string,
) string {
	values := url.Values{
		"client_id": {
			testAuthorizationClientID,
		},
		"redirect_uri": {
			testAuthorizationRedirect,
		},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {testAuthorizationState},
		"nonce":         {testAuthorizationNonce},
		"code_challenge": {
			testAuthorizationPKCE,
		},
		"code_challenge_method": {"S256"},
	}

	for name, value := range overrides {
		if value == "" {
			values.Del(name)
			continue
		}

		values.Set(name, value)
	}

	return "/oauth/authorize?" + values.Encode()
}

func assertAuthorizationErrorRedirect(
	t *testing.T,
	response *http.Response,
	expectedError string,
	expectedState string,
) {
	t.Helper()

	location := response.Header.Get("Location")
	if location == "" {
		t.Fatal("expected authorization error redirect")
	}

	destination, err := url.Parse(location)
	if err != nil {
		t.Fatalf(
			"parse authorization redirect: %v",
			err,
		)
	}

	expectedDestination, err := url.Parse(
		testAuthorizationRedirect,
	)
	if err != nil {
		t.Fatalf(
			"parse expected redirect: %v",
			err,
		)
	}

	if destination.Scheme != expectedDestination.Scheme ||
		destination.Host != expectedDestination.Host ||
		destination.Path != expectedDestination.Path {
		t.Fatalf(
			"unexpected authorization redirect %q",
			location,
		)
	}

	query := destination.Query()

	if query.Get("source") != "gatehouse" {
		t.Fatal("registered redirect query was not preserved")
	}

	if query.Get("error") != expectedError {
		t.Fatalf(
			"expected OAuth error %q, got %q",
			expectedError,
			query.Get("error"),
		)
	}

	if query.Get("state") != expectedState {
		t.Fatalf(
			"expected state %q, got %q",
			expectedState,
			query.Get("state"),
		)
	}
}

func assertAuthorizationTransactionCount(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	expected int64,
) {
	t.Helper()

	var actual int64
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM authorization_transactions`,
	).Scan(&actual); err != nil {
		t.Fatalf(
			"count authorization transactions: %v",
			err,
		)
	}

	if actual != expected {
		t.Fatalf(
			"expected %d authorization transactions, got %d",
			expected,
			actual,
		)
	}
}
