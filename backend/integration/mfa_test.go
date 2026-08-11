package integration_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
)

type mfaCurrentUserState struct {
	AuthenticationLevel string `json:"authentication_level"`
	MFARequired         bool   `json:"mfa_required"`
	MFAEnrolled         bool   `json:"mfa_enrolled"`
	FullyAuthenticated  bool   `json:"fully_authenticated"`
}

func TestMFAStateMachineAndAdversarialCases(t *testing.T) {
	ctx := context.Background()
	authentication, pool := newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "MFA Company",
			TenantSlug:  "mfa-company",
			Email:       "owner@mfa.test",
			DisplayName: "MFA Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register MFA user: %v", err)
	}

	commandTag, err := pool.Exec(
		ctx,
		`
			UPDATE tenants
			SET mfa_required = true
			WHERE id = $1
		`,
		registration.TenantID,
	)
	if err != nil {
		t.Fatalf("require tenant MFA: %v", err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatal("expected one updated tenant")
	}

	router := httpapi.NewRouter(
		httpapi.Dependencies{
			Authentication: authentication,
			SessionCookie:  httpapi.NewSessionCookie(true),
		},
	)

	passwordCookie := loginMFAUser(t, router, nil)

	assertMFAState(
		t,
		router,
		passwordCookie,
		mfaCurrentUserState{
			AuthenticationLevel: "password",
			MFARequired:         true,
			MFAEnrolled:         false,
			FullyAuthenticated:  false,
		},
	)

	enrollmentResponse := performRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/mfa/enroll",
		nil,
		passwordCookie,
	)

	enrollmentBody := requireResponseStatus(
		t,
		enrollmentResponse,
		http.StatusOK,
	)

	var enrollment struct {
		ProvisioningURI string `json:"provisioning_uri"`
		ManualKey       string `json:"manual_key"`
	}
	if err := json.Unmarshal(enrollmentBody, &enrollment); err != nil {
		t.Fatalf("decode enrollment response: %v", err)
	}

	secret := decodeEnrollmentSecret(t, enrollment)
	assertEncryptedTOTPSecret(
		t,
		ctx,
		pool,
		registration.UserID,
		secret,
	)
	assertTOTPCredentialStatus(t, ctx, pool, "pending")
	assertAvailableRecoveryCodes(t, ctx, pool, 0)

	confirmationTime := time.Now()
	confirmationCode, err := auth.GenerateTOTPCode(
		secret,
		confirmationTime,
	)
	if err != nil {
		t.Fatalf("generate confirmation code: %v", err)
	}

	wrongCode := differentTOTPCode(t, confirmationCode)

	wrongConfirmation := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/enroll/confirm",
		map[string]string{"code": wrongCode},
		passwordCookie,
	)
	requireResponseStatus(
		t,
		wrongConfirmation,
		http.StatusUnauthorized,
	)

	assertTOTPCredentialStatus(t, ctx, pool, "pending")
	assertAvailableRecoveryCodes(t, ctx, pool, 0)

	assertMFAState(
		t,
		router,
		passwordCookie,
		mfaCurrentUserState{
			AuthenticationLevel: "password",
			MFARequired:         true,
			MFAEnrolled:         false,
			FullyAuthenticated:  false,
		},
	)

	validConfirmation := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/enroll/confirm",
		map[string]string{"code": confirmationCode},
		passwordCookie,
	)

	confirmationBody := requireResponseStatus(
		t,
		validConfirmation,
		http.StatusOK,
	)

	confirmedCookie := requireSessionCookie(
		t,
		validConfirmation,
	)
	if confirmedCookie.Value == passwordCookie.Value {
		t.Fatal("MFA confirmation did not rotate the session")
	}

	var confirmation struct {
		AuthenticationLevel string   `json:"authentication_level"`
		RecoveryCodes       []string `json:"recovery_codes"`
	}
	if err := json.Unmarshal(confirmationBody, &confirmation); err != nil {
		t.Fatalf("decode confirmation response: %v", err)
	}

	if confirmation.AuthenticationLevel != "mfa" {
		t.Fatalf(
			"expected MFA authentication level, got %q",
			confirmation.AuthenticationLevel,
		)
	}

	if len(confirmation.RecoveryCodes) != 10 {
		t.Fatalf(
			"expected 10 recovery codes, got %d",
			len(confirmation.RecoveryCodes),
		)
	}

	assertUnauthorizedCurrentUser(t, router, passwordCookie)

	assertMFAState(
		t,
		router,
		confirmedCookie,
		mfaCurrentUserState{
			AuthenticationLevel: "mfa",
			MFARequired:         true,
			MFAEnrolled:         true,
			FullyAuthenticated:  true,
		},
	)

	assertTOTPCredentialStatus(t, ctx, pool, "active")
	assertAvailableRecoveryCodes(t, ctx, pool, 10)

	recoveryCode := confirmation.RecoveryCodes[0]
	assertRecoveryCodeState(
		t,
		ctx,
		pool,
		recoveryCode,
		false,
	)

	// the confirmation timestep has already been consumed
	replayPasswordCookie := loginMFAUser(t, router, nil)

	replayedConfirmationCode := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/challenge/totp",
		map[string]string{"code": confirmationCode},
		replayPasswordCookie,
	)
	requireResponseStatus(
		t,
		replayedConfirmationCode,
		http.StatusUnauthorized,
	)

	// a failed challenge must not revoke the password session
	assertMFAState(
		t,
		router,
		replayPasswordCookie,
		mfaCurrentUserState{
			AuthenticationLevel: "password",
			MFARequired:         true,
			MFAEnrolled:         true,
			FullyAuthenticated:  false,
		},
	)

	// use the next allowed clock step so the test does not sleep
	nextCode, err := auth.GenerateTOTPCode(
		secret,
		confirmationTime.Add(30*time.Second),
	)
	if err != nil {
		t.Fatalf("generate next TOTP code: %v", err)
	}

	validChallenge := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/challenge/totp",
		map[string]string{"code": nextCode},
		replayPasswordCookie,
	)

	requireResponseStatus(t, validChallenge, http.StatusOK)
	challengedCookie := requireSessionCookie(t, validChallenge)

	if challengedCookie.Value == replayPasswordCookie.Value {
		t.Fatal("TOTP challenge did not rotate the session")
	}

	assertUnauthorizedCurrentUser(
		t,
		router,
		replayPasswordCookie,
	)

	assertMFAState(
		t,
		router,
		challengedCookie,
		mfaCurrentUserState{
			AuthenticationLevel: "mfa",
			MFARequired:         true,
			MFAEnrolled:         true,
			FullyAuthenticated:  true,
		},
	)

	// the successful challenge code must not work again
	secondReplayPassword := loginMFAUser(t, router, nil)

	replayedChallenge := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/challenge/totp",
		map[string]string{"code": nextCode},
		secondReplayPassword,
	)
	requireResponseStatus(
		t,
		replayedChallenge,
		http.StatusUnauthorized,
	)

	// recovery code succeeds once and rotates the password session
	recoveryPasswordCookie := loginMFAUser(t, router, nil)

	recoveryChallenge := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/challenge/recovery",
		map[string]string{"recovery_code": recoveryCode},
		recoveryPasswordCookie,
	)

	requireResponseStatus(t, recoveryChallenge, http.StatusOK)
	recoveryMFACookie := requireSessionCookie(t, recoveryChallenge)

	if recoveryMFACookie.Value == recoveryPasswordCookie.Value {
		t.Fatal("recovery challenge did not rotate the session")
	}

	assertUnauthorizedCurrentUser(
		t,
		router,
		recoveryPasswordCookie,
	)

	assertMFAState(
		t,
		router,
		recoveryMFACookie,
		mfaCurrentUserState{
			AuthenticationLevel: "mfa",
			MFARequired:         true,
			MFAEnrolled:         true,
			FullyAuthenticated:  true,
		},
	)

	assertRecoveryCodeState(
		t,
		ctx,
		pool,
		recoveryCode,
		true,
	)
	assertAvailableRecoveryCodes(t, ctx, pool, 9)

	// reusing the consumed recovery code must fail without revoking
	// the current password-level session
	reusePasswordCookie := loginMFAUser(t, router, nil)

	reusedRecoveryCode := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/mfa/challenge/recovery",
		map[string]string{"recovery_code": recoveryCode},
		reusePasswordCookie,
	)
	requireResponseStatus(
		t,
		reusedRecoveryCode,
		http.StatusUnauthorized,
	)

	assertMFAState(
		t,
		router,
		reusePasswordCookie,
		mfaCurrentUserState{
			AuthenticationLevel: "password",
			MFARequired:         true,
			MFAEnrolled:         true,
			FullyAuthenticated:  false,
		},
	)
}

func newIntegrationMFASecretCipher(
	t *testing.T,
) *auth.AESGCMSecretCipher {
	t.Helper()

	key := bytes.Repeat([]byte{0x4d}, 32)

	secretCipher, err := auth.NewAESGCMSecretCipher(
		"integration-v1",
		key,
	)
	if err != nil {
		t.Fatalf("create integration MFA cipher: %v", err)
	}

	return secretCipher
}

func loginMFAUser(
	t *testing.T,
	router http.Handler,
	previousCookie *http.Cookie,
) *http.Cookie {
	t.Helper()

	response := performMFAJSONRequest(
		t,
		router,
		"/api/v1/auth/login",
		map[string]string{
			"tenant_slug": "mfa-company",
			"email":       "owner@mfa.test",
			"password":    "correct horse battery staple",
		},
		previousCookie,
	)

	requireResponseStatus(t, response, http.StatusOK)
	return requireSessionCookie(t, response)
}

func performMFAJSONRequest(
	t *testing.T,
	router http.Handler,
	target string,
	value any,
	sessionCookie *http.Cookie,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode request body: %v", err)
	}

	return performRequest(
		t,
		router,
		http.MethodPost,
		target,
		bytes.NewReader(body),
		sessionCookie,
	)
}

func requireResponseStatus(
	t *testing.T,
	response *http.Response,
	expectedStatus int,
) []byte {
	t.Helper()

	actualStatus := response.StatusCode
	body := readResponseBody(t, response)

	if actualStatus != expectedStatus {
		t.Fatalf(
			"expected status %d, got %d: %s",
			expectedStatus,
			actualStatus,
			body,
		)
	}

	return body
}

func decodeEnrollmentSecret(
	t *testing.T,
	enrollment struct {
		ProvisioningURI string `json:"provisioning_uri"`
		ManualKey       string `json:"manual_key"`
	},
) []byte {
	t.Helper()

	parsedURI, err := url.Parse(enrollment.ProvisioningURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}

	if parsedURI.Scheme != "otpauth" ||
		parsedURI.Host != "totp" {
		t.Fatalf(
			"unexpected provisioning URI %q",
			enrollment.ProvisioningURI,
		)
	}

	if parsedURI.Query().Get("secret") != enrollment.ManualKey {
		t.Fatal("manual key and provisioning URI secret differ")
	}

	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)

	secret, err := encoding.DecodeString(enrollment.ManualKey)
	if err != nil {
		t.Fatalf("decode enrollment secret: %v", err)
	}

	return secret
}

func assertEncryptedTOTPSecret(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	userID pgtype.UUID,
	plaintextSecret []byte,
) {
	t.Helper()

	var ciphertext []byte
	var nonce []byte
	var keyID string

	if err := pool.QueryRow(
		ctx,
		`
			SELECT
				secret_ciphertext,
				secret_nonce,
				encryption_key_id
			FROM totp_credentials
			WHERE user_id = $1
		`,
		userID,
	).Scan(&ciphertext, &nonce, &keyID); err != nil {
		t.Fatalf("load encrypted TOTP secret: %v", err)
	}

	if bytes.Equal(ciphertext, plaintextSecret) ||
		bytes.Contains(ciphertext, plaintextSecret) {
		t.Fatal("database exposed the plaintext TOTP secret")
	}

	if len(nonce) != 12 {
		t.Fatalf("expected 12-byte nonce, got %d", len(nonce))
	}

	decrypted, err := newIntegrationMFASecretCipher(t).Decrypt(
		userID,
		auth.EncryptedMFASecret{
			Ciphertext: ciphertext,
			Nonce:      nonce,
			KeyID:      keyID,
		},
	)
	if err != nil {
		t.Fatalf("decrypt stored TOTP secret: %v", err)
	}

	if !bytes.Equal(decrypted, plaintextSecret) {
		t.Fatal("stored TOTP secret did not decrypt correctly")
	}
}

func assertTOTPCredentialStatus(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	expected string,
) {
	t.Helper()

	var actual string
	if err := pool.QueryRow(
		ctx,
		`SELECT status FROM totp_credentials`,
	).Scan(&actual); err != nil {
		t.Fatalf("load TOTP credential status: %v", err)
	}

	if actual != expected {
		t.Fatalf(
			"expected TOTP status %q, got %q",
			expected,
			actual,
		)
	}
}

func assertAvailableRecoveryCodes(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	expected int64,
) {
	t.Helper()

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM mfa_recovery_codes
			WHERE consumed_at IS NULL
		`,
		expected,
	)
}

func assertRecoveryCodeState(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	rawCode string,
	expectedConsumed bool,
) {
	t.Helper()

	codeHash, err := auth.HashRecoveryCode(rawCode)
	if err != nil {
		t.Fatalf("hash recovery code: %v", err)
	}

	var consumed bool
	if err := pool.QueryRow(
		ctx,
		`
			SELECT consumed_at IS NOT NULL
			FROM mfa_recovery_codes
			WHERE code_hash = $1
		`,
		codeHash,
	).Scan(&consumed); err != nil {
		t.Fatalf("load recovery code state: %v", err)
	}

	if consumed != expectedConsumed {
		t.Fatalf(
			"expected recovery consumed=%t, got %t",
			expectedConsumed,
			consumed,
		)
	}
}

func assertMFAState(
	t *testing.T,
	router http.Handler,
	sessionCookie *http.Cookie,
	expected mfaCurrentUserState,
) {
	t.Helper()

	response := performRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/auth/current-user",
		nil,
		sessionCookie,
	)

	body := requireResponseStatus(t, response, http.StatusOK)

	var actual mfaCurrentUserState
	if err := json.Unmarshal(body, &actual); err != nil {
		t.Fatalf("decode current-user MFA state: %v", err)
	}

	if actual != expected {
		t.Fatalf(
			"expected MFA state %+v, got %+v",
			expected,
			actual,
		)
	}
}

func differentTOTPCode(
	t *testing.T,
	code string,
) string {
	t.Helper()

	value, err := strconv.Atoi(code)
	if err != nil {
		t.Fatalf("parse TOTP code: %v", err)
	}

	return fmt.Sprintf("%06d", (value+1)%1_000_000)
}
