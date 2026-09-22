package federation

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type fakeCallbackStore struct {
	transaction    store.UpstreamOidcTransaction
	transactionErr error
	stateHash      []byte
	consumeCalls   int

	connection      store.UpstreamOidcConnection
	connectionErr   error
	connectionInput store.GetEnabledUpstreamOIDCConnectionByIDParams
	connectionCalls int
}

func (fake *fakeCallbackStore) ConsumeUpstreamOIDCTransaction(
	_ context.Context,
	stateHash []byte,
) (store.UpstreamOidcTransaction, error) {
	fake.consumeCalls++
	fake.stateHash = append([]byte(nil), stateHash...)

	return fake.transaction, fake.transactionErr
}

func (fake *fakeCallbackStore) GetEnabledUpstreamOIDCConnectionByID(
	_ context.Context,
	input store.GetEnabledUpstreamOIDCConnectionByIDParams,
) (store.UpstreamOidcConnection, error) {
	fake.connectionCalls++
	fake.connectionInput = input

	return fake.connection, fake.connectionErr
}

type fakeTokenExchanger struct {
	response TokenResponse
	err      error
	input    TokenExchangeInput
	calls    int
}

func (fake *fakeTokenExchanger) Exchange(
	_ context.Context,
	input TokenExchangeInput,
) (TokenResponse, error) {
	fake.calls++

	// Copy the secret because the callback deliberately clears its
	// decrypted byte slice after use.
	input.ClientSecret = append(
		[]byte(nil),
		input.ClientSecret...,
	)
	fake.input = input

	return fake.response, fake.err
}

type fakeUpstreamIdentityVerifier struct {
	identity VerifiedIdentity
	err      error
	input    IDTokenVerificationInput
	calls    int
}

func (fake *fakeUpstreamIdentityVerifier) Verify(
	_ context.Context,
	input IDTokenVerificationInput,
) (VerifiedIdentity, error) {
	fake.calls++
	input.NonceHash = append(
		[]byte(nil),
		input.NonceHash...,
	)
	fake.input = input

	return fake.identity, fake.err
}

type fakeUpstreamSessionIssuer struct {
	session auth.SessionGrant
	err     error
	input   auth.CreateUpstreamSessionInput
	calls   int
}

func (fake *fakeUpstreamSessionIssuer) CreateUpstreamSession(
	_ context.Context,
	input auth.CreateUpstreamSessionInput,
) (auth.SessionGrant, error) {
	fake.calls++
	fake.input = input

	return fake.session, fake.err
}

type callbackTestFixture struct {
	service       *AuthorizationCallbackService
	artifacts     AuthorizationArtifacts
	connection    store.UpstreamOidcConnection
	store         *fakeCallbackStore
	discovery     *fakeProviderDiscovery
	tokenClient   *fakeTokenExchanger
	verifier      *fakeUpstreamIdentityVerifier
	sessionIssuer *fakeUpstreamSessionIssuer
}

func newCallbackTestFixture(
	t *testing.T,
) callbackTestFixture {
	t.Helper()

	artifacts, err :=
		GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf(
			"generate authorization artifacts: %v",
			err,
		)
	}

	connection := testUpstreamConnection()

	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		30,
	)

	encryptedVerifier, err :=
		secretCipher.Encrypt(
			connection.TenantID,
			SecretPurposePKCEVerifier,
			[]byte(artifacts.PKCEVerifier),
		)
	if err != nil {
		t.Fatalf("encrypt PKCE verifier: %v", err)
	}

	encryptedClientSecret, err :=
		secretCipher.Encrypt(
			connection.TenantID,
			SecretPurposeClientSecret,
			[]byte("upstream-client-secret"),
		)
	if err != nil {
		t.Fatalf("encrypt client secret: %v", err)
	}

	connection.ClientSecretCiphertext =
		encryptedClientSecret.Ciphertext
	connection.ClientSecretNonce =
		encryptedClientSecret.Nonce
	connection.EncryptionKeyID =
		encryptedClientSecret.KeyID

	callbackStore := &fakeCallbackStore{
		transaction: store.UpstreamOidcTransaction{
			StateHash:    artifacts.StateHash,
			TenantID:     connection.TenantID,
			ConnectionID: connection.ID,
			NonceHash:    artifacts.NonceHash,

			PkceVerifierCiphertext: encryptedVerifier.Ciphertext,
			PkceVerifierNonce:      encryptedVerifier.Nonce,
			EncryptionKeyID:        encryptedVerifier.KeyID,

			ReturnPath: "/dashboard",
			ExpiresAt: pgtype.Timestamptz{
				Time: time.Now().
					Add(5 * time.Minute),
				Valid: true,
			},
			ConsumedAt: pgtype.Timestamptz{
				Time:  time.Now(),
				Valid: true,
			},
		},
		connection: connection,
	}

	discovery := &fakeProviderDiscovery{
		document: validDiscoveryDocument(
			connection.Issuer,
		),
	}

	tokenClient := &fakeTokenExchanger{
		response: TokenResponse{
			AccessToken: "upstream-access-token",
			TokenType:   "Bearer",
			ExpiresIn:   300,
			IDToken:     "signed.upstream.id-token",
			Scope:       "openid",
		},
	}

	verifier := &fakeUpstreamIdentityVerifier{
		identity: VerifiedIdentity{
			Subject: "external-user-123",
		},
	}

	sessionIssuer := &fakeUpstreamSessionIssuer{
		session: auth.SessionGrant{
			Token:        "gatehouse-session-token",
			SessionID:    federationTestUUID(40),
			TenantID:     connection.TenantID,
			MembershipID: federationTestUUID(41),
			UserID:       federationTestUUID(42),
			ExpiresAt: time.Now().
				Add(12 * time.Hour),
		},
	}

	service, err :=
		NewAuthorizationCallbackService(
			callbackStore,
			discovery,
			tokenClient,
			verifier,
			secretCipher,
			sessionIssuer,
			"https://gatehouse.example.com/api/v1/auth/federation/callback",
		)
	if err != nil {
		t.Fatalf(
			"create callback service: %v",
			err,
		)
	}

	return callbackTestFixture{
		service:       service,
		artifacts:     artifacts,
		connection:    connection,
		store:         callbackStore,
		discovery:     discovery,
		tokenClient:   tokenClient,
		verifier:      verifier,
		sessionIssuer: sessionIssuer,
	}
}

func TestAuthorizationCallbackCompletesFederation(
	t *testing.T,
) {
	fixture := newCallbackTestFixture(t)

	result, err := fixture.service.Complete(
		t.Context(),
		CompleteAuthorizationInput{
			State:           fixture.artifacts.State,
			Code:            "upstream-authorization-code",
			PreviousSession: "previous-gatehouse-session",
		},
	)
	if err != nil {
		t.Fatalf(
			"complete authorization: %v",
			err,
		)
	}

	if result.ReturnPath != "/dashboard" ||
		result.Session.Token !=
			"gatehouse-session-token" {
		t.Fatalf(
			"unexpected callback result: %+v",
			result,
		)
	}

	if fixture.store.consumeCalls != 1 ||
		!bytes.Equal(
			fixture.store.stateHash,
			fixture.artifacts.StateHash,
		) {
		t.Fatal(
			"authorization state was not consumed correctly",
		)
	}

	if fixture.store.connectionCalls != 1 ||
		fixture.store.connectionInput.TenantID !=
			fixture.connection.TenantID ||
		fixture.store.connectionInput.ConnectionID !=
			fixture.connection.ID {
		t.Fatalf(
			"unexpected connection lookup: %+v",
			fixture.store.connectionInput,
		)
	}

	tokenInput := fixture.tokenClient.input
	if fixture.tokenClient.calls != 1 ||
		tokenInput.ClientID !=
			fixture.connection.ClientID ||
		string(tokenInput.ClientSecret) !=
			"upstream-client-secret" ||
		tokenInput.Code !=
			"upstream-authorization-code" ||
		tokenInput.PKCEVerifier !=
			fixture.artifacts.PKCEVerifier ||
		tokenInput.RedirectURI !=
			"https://gatehouse.example.com/api/v1/auth/federation/callback" {
		t.Fatalf(
			"unexpected token exchange: %+v",
			tokenInput,
		)
	}

	verificationInput := fixture.verifier.input
	if fixture.verifier.calls != 1 ||
		verificationInput.IDToken !=
			"signed.upstream.id-token" ||
		verificationInput.ExpectedIssuer !=
			fixture.connection.Issuer ||
		verificationInput.ClientID !=
			fixture.connection.ClientID ||
		verificationInput.JWKSURI !=
			fixture.discovery.document.JWKSURI ||
		!bytes.Equal(
			verificationInput.NonceHash,
			fixture.artifacts.NonceHash,
		) {
		t.Fatalf(
			"unexpected ID token verification: %+v",
			verificationInput,
		)
	}

	sessionInput := fixture.sessionIssuer.input
	if fixture.sessionIssuer.calls != 1 ||
		sessionInput.TenantID !=
			fixture.connection.TenantID ||
		sessionInput.ConnectionID !=
			fixture.connection.ID ||
		sessionInput.Subject !=
			"external-user-123" ||
		sessionInput.PreviousSession !=
			"previous-gatehouse-session" {
		t.Fatalf(
			"unexpected session input: %+v",
			sessionInput,
		)
	}
}

func TestAuthorizationCallbackRejectsUnknownOrReusedState(
	t *testing.T,
) {
	fixture := newCallbackTestFixture(t)
	fixture.store.transactionErr = pgx.ErrNoRows

	_, err := fixture.service.Complete(
		t.Context(),
		CompleteAuthorizationInput{
			State: fixture.artifacts.State,
			Code:  "upstream-authorization-code",
		},
	)
	if !errors.Is(
		err,
		ErrInvalidAuthorizationCallback,
	) {
		t.Fatalf(
			"expected invalid callback, got %v",
			err,
		)
	}

	if fixture.store.consumeCalls != 1 ||
		fixture.tokenClient.calls != 0 ||
		fixture.verifier.calls != 0 ||
		fixture.sessionIssuer.calls != 0 {
		t.Fatal(
			"reused state progressed beyond transaction consumption",
		)
	}
}

func TestAuthorizationCallbackConsumesProviderDenial(
	t *testing.T,
) {
	fixture := newCallbackTestFixture(t)

	_, err := fixture.service.Complete(
		t.Context(),
		CompleteAuthorizationInput{
			State:         fixture.artifacts.State,
			ProviderError: "access_denied",
		},
	)
	if !errors.Is(
		err,
		ErrUpstreamAuthorizationDenied,
	) {
		t.Fatalf(
			"expected upstream denial, got %v",
			err,
		)
	}

	if fixture.store.consumeCalls != 1 ||
		fixture.store.connectionCalls != 0 ||
		fixture.tokenClient.calls != 0 ||
		fixture.sessionIssuer.calls != 0 {
		t.Fatal(
			"provider denial progressed after consuming state",
		)
	}
}

func TestAuthorizationCallbackRejectsUnverifiedToken(
	t *testing.T,
) {
	fixture := newCallbackTestFixture(t)
	fixture.verifier.err = ErrInvalidIDToken

	_, err := fixture.service.Complete(
		t.Context(),
		CompleteAuthorizationInput{
			State: fixture.artifacts.State,
			Code:  "upstream-authorization-code",
		},
	)
	if !errors.Is(
		err,
		ErrFederationUnavailable,
	) {
		t.Fatalf(
			"expected federation failure, got %v",
			err,
		)
	}

	if fixture.verifier.calls != 1 ||
		fixture.sessionIssuer.calls != 0 {
		t.Fatal(
			"unverified identity received a session",
		)
	}
}

func TestAuthorizationCallbackRejectsUnmappedIdentity(
	t *testing.T,
) {
	fixture := newCallbackTestFixture(t)
	fixture.sessionIssuer.err =
		auth.ErrInactiveMembership

	_, err := fixture.service.Complete(
		t.Context(),
		CompleteAuthorizationInput{
			State: fixture.artifacts.State,
			Code:  "upstream-authorization-code",
		},
	)
	if !errors.Is(
		err,
		ErrUpstreamIdentityNotMapped,
	) {
		t.Fatalf(
			"expected unmapped identity error, got %v",
			err,
		)
	}

	if fixture.sessionIssuer.calls != 1 {
		t.Fatal(
			"expected one mapped-session attempt",
		)
	}
}

func TestAuthorizationCallbackRejectsMalformedStateWithoutLookup(
	t *testing.T,
) {
	fixture := newCallbackTestFixture(t)

	_, err := fixture.service.Complete(
		t.Context(),
		CompleteAuthorizationInput{
			State: "not-a-valid-state",
			Code:  "upstream-authorization-code",
		},
	)
	if !errors.Is(
		err,
		ErrInvalidAuthorizationCallback,
	) {
		t.Fatalf(
			"expected invalid callback, got %v",
			err,
		)
	}

	if fixture.store.consumeCalls != 0 {
		t.Fatal(
			"malformed state should not reach storage",
		)
	}
}
