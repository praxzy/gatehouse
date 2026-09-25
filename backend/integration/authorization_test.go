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

	"github.com/praxzy/gatehouse/backend/internal/audit"
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
		oidc.NewAuthorizationService(
			pool,
			audit.NewWriter(),
		)
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

			requireResponseStatus(
				t,
				response,
				http.StatusFound,
			)

			loginLocation := response.Header.Get("Location")
			if loginLocation == "" {
				t.Fatal("expected login redirect")
			}

			loginTarget, err := url.Parse(loginLocation)
			if err != nil {
				t.Fatalf("parse login redirect: %v", err)
			}

			if loginTarget.Path != "/login" {
				t.Fatalf(
					"expected login redirect, got %q",
					loginLocation,
				)
			}

			if loginTarget.Query().Get("tenant_slug") !=
				"authorization-company" {
				t.Fatalf(
					"unexpected login tenant %q",
					loginTarget.Query().Get("tenant_slug"),
				)
			}

			returnTo := loginTarget.Query().Get("return_to")
			if returnTo == "" {
				t.Fatal("login redirect did not preserve continuation")
			}

			continuation, err := url.Parse(returnTo)
			if err != nil {
				t.Fatalf(
					"parse authorization continuation: %v",
					err,
				)
			}

			if continuation.Path !=
				"/oauth/authorize/continue" {
				t.Fatalf(
					"unexpected continuation path %q",
					continuation.Path,
				)
			}

			if continuation.Query().Get("state") !=
				testAuthorizationState {
				t.Fatal(
					"authorization state was not preserved",
				)
			}

			parsedID, err := uuid.Parse(
				continuation.Query().Get(
					"transaction_id",
				),
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
				t.Fatal(
					"authorization nonce was not preserved",
				)
			}

			if storedChallenge != testAuthorizationPKCE {
				t.Fatal("PKCE challenge was not preserved")
			}

			if lifetime <= 0 ||
				lifetime > 5*time.Minute+time.Second {
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

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id IS NULL
			  AND actor_kind = 'anonymous'
			  AND event_type = 'authorization.request'
			  AND outcome = 'failure'
			  AND metadata = '{"failure_reason":"client_unavailable"}'::jsonb
		`,
		2,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.request'
			  AND outcome = 'failure'
			  AND metadata = '{"failure_reason":"pkce_required"}'::jsonb
		`,
		1,
		registration.TenantID,
		applicationID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.request'
			  AND outcome = 'failure'
			  AND metadata = '{"failure_reason":"unsupported_response_type"}'::jsonb
		`,
		1,
		registration.TenantID,
		applicationID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.request'
			  AND outcome = 'success'
			  AND metadata = '{
			      "response_type": "code",
			      "scope_count": 3,
			      "has_nonce": true
			  }'::jsonb
		`,
		1,
		registration.TenantID,
		applicationID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.decision'
			  AND outcome = 'denied'
			  AND metadata = '{
			      "authentication_level": "none",
			      "decision_reason": "login_required"
			  }'::jsonb
		`,
		1,
		registration.TenantID,
		applicationID,
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

func TestAuthorizationStateMachineRequiresMFAAndApplicationAccess(
	t *testing.T,
) {
	ctx := context.Background()

	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Policy Company",
			TenantSlug:  "policy-company",
			Email:       "owner@policy.test",
			DisplayName: "Policy Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register policy tenant: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
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
				status,
				access_mode
			)
			VALUES (
				$1,
				'Restricted Portal',
				$2,
				'public',
				'active',
				'allowed_roles'
			)
			RETURNING id
		`,
		registration.TenantID,
		testAuthorizationClientID,
	).Scan(&applicationID); err != nil {
		t.Fatalf(
			"create restricted application: %v",
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
			"create restricted redirect URI: %v",
			err,
		)
	}

	if _, err := pool.Exec(
		ctx,
		`
			INSERT INTO application_access (
				tenant_id,
				application_id,
				role_id
			)
			VALUES ($1, $2, $3)
		`,
		registration.TenantID,
		applicationID,
		registration.OwnerRoleID,
	); err != nil {
		t.Fatalf(
			"grant owner application access: %v",
			err,
		)
	}

	viewerMembershipID := createAuthorizationPolicyMember(
		t,
		ctx,
		pool,
		registration.TenantID,
	)

	authorization, err :=
		oidc.NewAuthorizationService(
			pool,
			audit.NewWriter(),
		)
	if err != nil {
		t.Fatalf(
			"create authorization service: %v",
			err,
		)
	}

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication:    authentication,
			OIDCAuthorization: authorization,
			SessionCookie:     httpapi.NewSessionCookie(true),
		},
	)

	ownerPasswordCookie := loginLifecycleUser(
		t,
		router,
		"policy-company",
		"owner@policy.test",
		"correct horse battery staple",
	)

	enrollmentResponse := performRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/mfa/enroll",
		nil,
		ownerPasswordCookie,
	)

	enrollmentBody := requireResponseStatus(
		t,
		enrollmentResponse,
		http.StatusOK,
	)

	var enrollment mfaEnrollmentResponse
	if err := json.Unmarshal(
		enrollmentBody,
		&enrollment,
	); err != nil {
		t.Fatalf(
			"decode policy MFA enrollment: %v",
			err,
		)
	}

	secret := decodeEnrollmentSecret(t, enrollment)
	confirmationTime := time.Now()

	confirmationCode, err := auth.GenerateTOTPCode(
		secret,
		confirmationTime,
	)
	if err != nil {
		t.Fatalf(
			"generate enrollment code: %v",
			err,
		)
	}

	confirmationResponse := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/enroll/confirm",
		map[string]string{
			"code": confirmationCode,
		},
		ownerPasswordCookie,
	)

	requireResponseStatus(
		t,
		confirmationResponse,
		http.StatusOK,
	)

	ownerMFACookie := requireSessionCookie(
		t,
		confirmationResponse,
	)

	t.Run(
		"valid fully authenticated SSO session is reused",
		func(t *testing.T) {
			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"state": "owner-sso-state-0123456789",
						"nonce": "owner-sso-nonce-0123456789",
					},
				),
				nil,
				ownerMFACookie,
			)

			requireAuthorizationGrant(
				t,
				response,
				"owner-sso-state-0123456789",
			)
		},
	)

	var challengeContinuation string

	t.Run(
		"password session cannot bypass required MFA",
		func(t *testing.T) {
			passwordCookie := loginLifecycleUser(
				t,
				router,
				"policy-company",
				"owner@policy.test",
				"correct horse battery staple",
			)

			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"state": "owner-mfa-state-0123456789",
						"nonce": "owner-mfa-nonce-0123456789",
					},
				),
				nil,
				passwordCookie,
			)

			challengeContinuation =
				requireAuthorizationFlowRedirect(
					t,
					response,
					"/mfa/challenge",
				)

			bypassResponse := performRequest(
				t,
				router,
				http.MethodGet,
				challengeContinuation,
				nil,
				passwordCookie,
			)

			requireAuthorizationFlowRedirect(
				t,
				bypassResponse,
				"/mfa/challenge",
			)

			nextCode, err := auth.GenerateTOTPCode(
				secret,
				confirmationTime.Add(30*time.Second),
			)
			if err != nil {
				t.Fatalf(
					"generate challenge code: %v",
					err,
				)
			}

			challengeResponse := performMFAJSONRequest(
				t,
				router,
				"/api/v1/auth/mfa/challenge/totp",
				map[string]string{
					"code": nextCode,
				},
				passwordCookie,
			)

			requireResponseStatus(
				t,
				challengeResponse,
				http.StatusOK,
			)

			challengedCookie := requireSessionCookie(
				t,
				challengeResponse,
			)

			grantedResponse := performRequest(
				t,
				router,
				http.MethodGet,
				challengeContinuation,
				nil,
				challengedCookie,
			)

			requireAuthorizationGrant(
				t,
				grantedResponse,
				"owner-mfa-state-0123456789",
			)
		},
	)

	viewerCookie := loginLifecycleUser(
		t,
		router,
		"policy-company",
		"viewer@policy.test",
		"correct horse battery staple",
	)

	t.Run(
		"member excluded by application policy is denied",
		func(t *testing.T) {
			const deniedState = "viewer-denied-state-0123456789"

			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"state": deniedState,
						"nonce": "viewer-denied-nonce-0123456789",
					},
				),
				nil,
				viewerCookie,
			)

			requireResponseStatus(
				t,
				response,
				http.StatusFound,
			)

			assertAuthorizationErrorRedirect(
				t,
				response,
				"access_denied",
				deniedState,
			)

			stateHash := sha256.Sum256(
				[]byte(deniedState),
			)

			var (
				deniedTransactionID pgtype.UUID
				consumedAt          pgtype.Timestamptz
			)

			if err := pool.QueryRow(
				ctx,
				`
					SELECT
						id,
						consumed_at
					FROM authorization_transactions
					WHERE state_hash = $1
				`,
				stateHash[:],
			).Scan(
				&deniedTransactionID,
				&consumedAt,
			); err != nil {
				t.Fatalf(
					"load denied transaction: %v",
					err,
				)
			}

			if !consumedAt.Valid {
				t.Fatal(
					"denied transaction was not consumed",
				)
			}

			replayTarget :=
				authorizationContinuationTargetForTest(
					deniedTransactionID,
					deniedState,
				)

			replayResponse := performRequest(
				t,
				router,
				http.MethodGet,
				replayTarget,
				nil,
				viewerCookie,
			)

			requireResponseStatus(
				t,
				replayResponse,
				http.StatusBadRequest,
			)

			if location :=
				replayResponse.Header.Get("Location"); location != "" {
				t.Fatalf(
					"consumed denial redirected to %q",
					location,
				)
			}
		},
	)

	t.Run(
		"role change allows previously denied member",
		func(t *testing.T) {
			updateResponse := performLifecycleJSONRequest(
				t,
				router,
				http.MethodPatch,
				"/api/v1/members/"+
					lifecycleUUID(t, viewerMembershipID),
				map[string]any{
					"role_id": lifecycleUUID(
						t,
						registration.OwnerRoleID,
					),
				},
				ownerMFACookie,
			)

			requireResponseStatus(
				t,
				updateResponse,
				http.StatusNoContent,
			)

			const allowedState = "viewer-allowed-state-0123456789"

			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"state": allowedState,
						"nonce": "viewer-allowed-nonce-0123456789",
					},
				),
				nil,
				viewerCookie,
			)

			requireAuthorizationGrant(
				t,
				response,
				allowedState,
			)
		},
	)

	t.Run(
		"revoked SSO session requires reauthentication",
		func(t *testing.T) {
			session, err := authentication.ResolveSession(
				ctx,
				ownerMFACookie.Value,
			)
			if err != nil {
				t.Fatalf(
					"resolve owner session before revocation: %v",
					err,
				)
			}

			if err := authentication.RevokeSession(
				ctx,
				session,
				"security integration test",
			); err != nil {
				t.Fatalf(
					"revoke owner session: %v",
					err,
				)
			}

			const revokedState =
				"revoked-session-state-0123456789"

			response := performRequest(
				t,
				router,
				http.MethodGet,
				authorizationRequestTarget(
					map[string]string{
						"state": revokedState,
						"nonce": "revoked-session-nonce-0123456789",
					},
				),
				nil,
				ownerMFACookie,
			)

			continuation :=
				requireAuthorizationFlowRedirect(
					t,
					response,
					"/login",
				)

			if continuation == "" {
				t.Fatal(
					"login redirect did not preserve authorization continuation",
				)
			}
		},
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.decision'
			  AND outcome = 'success'
			  AND metadata->>'decision_reason' =
			      'application_access_granted'
			  AND metadata ? 'authentication_level'
		`,
		3,
		registration.TenantID,
		applicationID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.decision'
			  AND outcome = 'denied'
			  AND metadata = '{
			      "authentication_level": "password",
			      "decision_reason": "mfa_challenge_required"
			  }'::jsonb
		`,
		2,
		registration.TenantID,
		applicationID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.decision'
			  AND outcome = 'denied'
			  AND metadata = '{
			      "authentication_level": "password",
			      "decision_reason": "application_access_denied"
			  }'::jsonb
		`,
		1,
		registration.TenantID,
		applicationID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND application_id = $2
			  AND event_type = 'authorization.code_issued'
			  AND outcome = 'success'
			  AND subject_type = 'authorization_transaction'
			  AND metadata = '{"expires_in_seconds":60}'::jsonb
		`,
		3,
		registration.TenantID,
		applicationID,
	)
}

func createAuthorizationPolicyMember(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID pgtype.UUID,
) pgtype.UUID {
	t.Helper()

	passwordHash, err := auth.HashPassword(
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf(
			"hash policy member password: %v",
			err,
		)
	}

	transaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf(
			"begin policy member transaction: %v",
			err,
		)
	}
	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	var userID pgtype.UUID
	if err := transaction.QueryRow(
		ctx,
		`
			INSERT INTO users (
				email,
				display_name,
				status,
				email_verified_at
			)
			VALUES (
				'viewer@policy.test',
				'Policy Viewer',
				'active',
				now()
			)
			RETURNING id
		`,
	).Scan(&userID); err != nil {
		t.Fatalf(
			"create policy member user: %v",
			err,
		)
	}

	if _, err := transaction.Exec(
		ctx,
		`
			INSERT INTO password_credentials (
				user_id,
				password_hash
			)
			VALUES ($1, $2)
		`,
		userID,
		passwordHash,
	); err != nil {
		t.Fatalf(
			"create policy member password: %v",
			err,
		)
	}

	var membershipID pgtype.UUID
	if err := transaction.QueryRow(
		ctx,
		`
			INSERT INTO memberships (
				tenant_id,
				user_id,
				status
			)
			VALUES ($1, $2, 'active')
			RETURNING id
		`,
		tenantID,
		userID,
	).Scan(&membershipID); err != nil {
		t.Fatalf(
			"create policy membership: %v",
			err,
		)
	}

	var memberRoleID pgtype.UUID
	if err := transaction.QueryRow(
		ctx,
		`
			SELECT id
			FROM roles
			WHERE tenant_id = $1
			  AND role_key = 'member'
		`,
		tenantID,
	).Scan(&memberRoleID); err != nil {
		t.Fatalf(
			"load policy member role: %v",
			err,
		)
	}

	if _, err := transaction.Exec(
		ctx,
		`
			INSERT INTO membership_roles (
				tenant_id,
				membership_id,
				role_id
			)
			VALUES ($1, $2, $3)
		`,
		tenantID,
		membershipID,
		memberRoleID,
	); err != nil {
		t.Fatalf(
			"assign policy member role: %v",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf(
			"commit policy member: %v",
			err,
		)
	}

	return membershipID
}

func requireAuthorizationFlowRedirect(
	t *testing.T,
	response *http.Response,
	expectedPath string,
) string {
	t.Helper()

	requireResponseStatus(
		t,
		response,
		http.StatusFound,
	)

	location := response.Header.Get("Location")
	if location == "" {
		t.Fatal("expected authorization flow redirect")
	}

	destination, err := url.Parse(location)
	if err != nil {
		t.Fatalf(
			"parse authorization flow redirect: %v",
			err,
		)
	}

	if destination.Path != expectedPath {
		t.Fatalf(
			"expected redirect to %q, got %q",
			expectedPath,
			destination.Path,
		)
	}

	returnTo := destination.Query().Get("return_to")
	if returnTo == "" {
		t.Fatal(
			"authorization flow redirect lost continuation",
		)
	}

	return returnTo
}

func requireAuthorizationGrant(
	t *testing.T,
	response *http.Response,
	expectedState string,
) string {
	t.Helper()

	requireResponseStatus(
		t,
		response,
		http.StatusFound,
	)

	location := response.Header.Get("Location")
	if location == "" {
		t.Fatal(
			"authorization grant omitted callback redirect",
		)
	}

	destination, err := url.Parse(location)
	if err != nil {
		t.Fatalf(
			"parse authorization callback: %v",
			err,
		)
	}

	expectedDestination, err := url.Parse(
		testAuthorizationRedirect,
	)
	if err != nil {
		t.Fatalf(
			"parse expected callback: %v",
			err,
		)
	}

	if destination.Scheme != expectedDestination.Scheme ||
		destination.Host != expectedDestination.Host ||
		destination.Path != expectedDestination.Path {
		t.Fatalf(
			"authorization code redirected to unexpected callback %q",
			location,
		)
	}

	query := destination.Query()

	if query.Get("source") != "gatehouse" {
		t.Fatal(
			"registered callback query was not preserved",
		)
	}

	if query.Get("state") != expectedState {
		t.Fatalf(
			"expected state %q, got %q",
			expectedState,
			query.Get("state"),
		)
	}

	code := query.Get("code")
	if len(code) != 48 ||
		code[:5] != "ghac_" {
		t.Fatalf(
			"authorization callback contained malformed code %q",
			code,
		)
	}

	if query.Get("error") != "" {
		t.Fatalf(
			"successful authorization included error %q",
			query.Get("error"),
		)
	}

	return code
}

func authorizationContinuationTargetForTest(
	transactionID pgtype.UUID,
	state string,
) string {
	transactionUUID := uuid.UUID(
		transactionID.Bytes,
	).String()

	query := url.Values{
		"transaction_id": {transactionUUID},
		"state":          {state},
	}

	return "/oauth/authorize/continue?" +
		query.Encode()
}
