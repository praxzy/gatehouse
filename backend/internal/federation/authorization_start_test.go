package federation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type fakeAuthorizationStore struct {
	connection store.UpstreamOidcConnection
	loadErr    error

	tenantSlug string
	loadCalls  int

	transactionParams store.CreateUpstreamOIDCTransactionParams
	transactionErr    error
	transactionCalls  int
}

func (fake *fakeAuthorizationStore) GetEnabledUpstreamOIDCConnectionByTenantSlug(
	_ context.Context,
	tenantSlug string,
) (store.UpstreamOidcConnection, error) {
	fake.loadCalls++
	fake.tenantSlug = tenantSlug

	return fake.connection, fake.loadErr
}

func (fake *fakeAuthorizationStore) CreateUpstreamOIDCTransaction(
	_ context.Context,
	params store.CreateUpstreamOIDCTransactionParams,
) (store.UpstreamOidcTransaction, error) {
	fake.transactionCalls++
	fake.transactionParams = params

	return store.UpstreamOidcTransaction{},
		fake.transactionErr
}

type fakeProviderDiscovery struct {
	document DiscoveryDocument
	err      error
	issuer   string
	calls    int
}

func (fake *fakeProviderDiscovery) Discover(
	_ context.Context,
	issuer string,
) (DiscoveryDocument, error) {
	fake.calls++
	fake.issuer = issuer

	return fake.document, fake.err
}

func testUpstreamConnection() store.UpstreamOidcConnection {
	return store.UpstreamOidcConnection{
		ID:          federationTestUUID(20),
		TenantID:    federationTestUUID(21),
		DisplayName: "Company SSO",
		Issuer:      "https://identity.example.com",
		ClientID:    "gatehouse-client",
		Status:      "enabled",
	}
}

func testAuthorizationService(
	t *testing.T,
	authorizationStore AuthorizationStore,
	discovery ProviderDiscovery,
) (*AuthorizationService, *AESGCMSecretCipher) {
	t.Helper()

	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		20,
	)

	service, err := NewAuthorizationService(
		authorizationStore,
		discovery,
		secretCipher,
		"https://gatehouse.example.com/api/v1/auth/federation/callback",
	)
	if err != nil {
		t.Fatalf(
			"create authorization service: %v",
			err,
		)
	}

	return service, secretCipher
}

func TestAuthorizationServiceBeginsFederation(
	t *testing.T,
) {
	connection := testUpstreamConnection()
	authorizationStore := &fakeAuthorizationStore{
		connection: connection,
	}
	discovery := &fakeProviderDiscovery{
		document: validDiscoveryDocument(
			connection.Issuer,
		),
	}

	service, secretCipher :=
		testAuthorizationService(
			t,
			authorizationStore,
			discovery,
		)

	now := time.Date(
		2026,
		time.September,
		20,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	service.now = func() time.Time {
		return now
	}

	returnPath :=
		"/oauth/authorize/continue?transaction=abc"

	result, err := service.Begin(
		t.Context(),
		BeginAuthorizationInput{
			TenantSlug: "example-company",
			ReturnPath: returnPath,
		},
	)
	if err != nil {
		t.Fatalf(
			"begin federation: %v",
			err,
		)
	}

	if result.ConnectionName !=
		connection.DisplayName {
		t.Fatalf(
			"unexpected connection name: %q",
			result.ConnectionName,
		)
	}

	expectedExpiry := now.Add(
		authorizationTransactionTTL,
	)
	if !result.ExpiresAt.Equal(expectedExpiry) {
		t.Fatalf(
			"unexpected expiry: %v",
			result.ExpiresAt,
		)
	}

	if authorizationStore.loadCalls != 1 ||
		authorizationStore.tenantSlug !=
			"example-company" ||
		discovery.calls != 1 ||
		discovery.issuer != connection.Issuer ||
		authorizationStore.transactionCalls != 1 {
		t.Fatalf(
			"unexpected service calls: store=%+v discovery=%+v",
			authorizationStore,
			discovery,
		)
	}

	authorizationURL, err := url.Parse(
		result.AuthorizationURL,
	)
	if err != nil {
		t.Fatalf(
			"parse authorization URL: %v",
			err,
		)
	}

	if authorizationURL.Scheme != "https" ||
		authorizationURL.Host !=
			"identity.example.com" ||
		authorizationURL.Path != "/authorize" {
		t.Fatalf(
			"unexpected authorization endpoint: %s",
			authorizationURL,
		)
	}

	query := authorizationURL.Query()

	expectedValues := map[string]string{
		"response_type":         "code",
		"client_id":             connection.ClientID,
		"redirect_uri":          "https://gatehouse.example.com/api/v1/auth/federation/callback",
		"scope":                 "openid",
		"code_challenge_method": "S256",
	}

	for key, expected := range expectedValues {
		if query.Get(key) != expected {
			t.Fatalf(
				"unexpected %s: %q",
				key,
				query.Get(key),
			)
		}
	}

	stateHash, err := HashAuthorizationState(
		query.Get("state"),
	)
	if err != nil {
		t.Fatalf("hash state: %v", err)
	}

	if !bytes.Equal(
		stateHash,
		authorizationStore.
			transactionParams.StateHash,
	) {
		t.Fatal(
			"stored state hash does not match redirect state",
		)
	}

	nonceHash, err := HashAuthorizationNonce(
		query.Get("nonce"),
	)
	if err != nil {
		t.Fatalf("hash nonce: %v", err)
	}

	if !bytes.Equal(
		nonceHash,
		authorizationStore.
			transactionParams.NonceHash,
	) {
		t.Fatal(
			"stored nonce hash does not match redirect nonce",
		)
	}

	params := authorizationStore.transactionParams

	if params.TenantID != connection.TenantID ||
		params.ConnectionID != connection.ID ||
		params.ReturnPath != returnPath ||
		!params.ExpiresAt.Valid ||
		!params.ExpiresAt.Time.Equal(expectedExpiry) {
		t.Fatalf(
			"unexpected transaction: %+v",
			params,
		)
	}

	verifier, err := secretCipher.Decrypt(
		connection.TenantID,
		SecretPurposePKCEVerifier,
		EncryptedSecret{
			Ciphertext: params.PkceVerifierCiphertext,
			Nonce:      params.PkceVerifierNonce,
			KeyID:      params.EncryptionKeyID,
		},
	)
	if err != nil {
		t.Fatalf(
			"decrypt stored verifier: %v",
			err,
		)
	}

	challengeHash := sha256.Sum256(verifier)
	expectedChallenge :=
		base64.RawURLEncoding.EncodeToString(
			challengeHash[:],
		)

	if query.Get("code_challenge") !=
		expectedChallenge {
		t.Fatal(
			"authorization URL is not bound to stored PKCE verifier",
		)
	}

	if bytes.Contains(
		params.PkceVerifierCiphertext,
		verifier,
	) {
		t.Fatal(
			"PKCE verifier was stored as plaintext",
		)
	}
}

func TestAuthorizationServiceUsesDefaultReturnPath(
	t *testing.T,
) {
	connection := testUpstreamConnection()
	authorizationStore := &fakeAuthorizationStore{
		connection: connection,
	}
	discovery := &fakeProviderDiscovery{
		document: validDiscoveryDocument(
			connection.Issuer,
		),
	}

	service, _ := testAuthorizationService(
		t,
		authorizationStore,
		discovery,
	)

	_, err := service.Begin(
		t.Context(),
		BeginAuthorizationInput{
			TenantSlug: "example-company",
		},
	)
	if err != nil {
		t.Fatalf(
			"begin federation: %v",
			err,
		)
	}

	if authorizationStore.
		transactionParams.ReturnPath != "/" {
		t.Fatalf(
			"unexpected default return path: %q",
			authorizationStore.
				transactionParams.ReturnPath,
		)
	}
}

func TestAuthorizationServiceRejectsInvalidInput(
	t *testing.T,
) {
	tests := []struct {
		name  string
		input BeginAuthorizationInput
	}{
		{
			name: "invalid tenant slug",
			input: BeginAuthorizationInput{
				TenantSlug: "Example_Company",
				ReturnPath: "/",
			},
		},
		{
			name: "scheme-relative return",
			input: BeginAuthorizationInput{
				TenantSlug: "example-company",
				ReturnPath: "//attacker.example.com",
			},
		},
		{
			name: "absolute return",
			input: BeginAuthorizationInput{
				TenantSlug: "example-company",
				ReturnPath: "https://attacker.example.com",
			},
		},
		{
			name: "backslash return",
			input: BeginAuthorizationInput{
				TenantSlug: "example-company",
				ReturnPath: `/\attacker`,
			},
		},
		{
			name: "encoded scheme-relative return",
			input: BeginAuthorizationInput{
				TenantSlug: "example-company",
				ReturnPath: "/%2fattacker.example.com",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizationStore :=
				&fakeAuthorizationStore{}
			discovery :=
				&fakeProviderDiscovery{}

			service, _ :=
				testAuthorizationService(
					t,
					authorizationStore,
					discovery,
				)

			_, err := service.Begin(
				t.Context(),
				test.input,
			)
			if !errors.Is(
				err,
				ErrInvalidBeginRequest,
			) {
				t.Fatalf(
					"expected invalid request, got %v",
					err,
				)
			}

			if authorizationStore.loadCalls != 0 ||
				authorizationStore.transactionCalls != 0 ||
				discovery.calls != 0 {
				t.Fatal(
					"invalid input reached dependencies",
				)
			}
		})
	}
}

func TestAuthorizationServiceDoesNotExposeUnknownTenant(
	t *testing.T,
) {
	authorizationStore := &fakeAuthorizationStore{
		loadErr: pgx.ErrNoRows,
	}
	discovery := &fakeProviderDiscovery{}

	service, _ := testAuthorizationService(
		t,
		authorizationStore,
		discovery,
	)

	_, err := service.Begin(
		t.Context(),
		BeginAuthorizationInput{
			TenantSlug: "unknown-company",
			ReturnPath: "/",
		},
	)
	if !errors.Is(
		err,
		ErrFederationUnavailable,
	) {
		t.Fatalf(
			"expected unavailable error, got %v",
			err,
		)
	}

	if discovery.calls != 0 ||
		authorizationStore.transactionCalls != 0 {
		t.Fatal(
			"unknown tenant created a transaction",
		)
	}
}

func TestAuthorizationServiceDoesNotPersistWhenDiscoveryFails(
	t *testing.T,
) {
	connection := testUpstreamConnection()
	authorizationStore := &fakeAuthorizationStore{
		connection: connection,
	}
	discovery := &fakeProviderDiscovery{
		err: ErrDiscoveryUnavailable,
	}

	service, _ := testAuthorizationService(
		t,
		authorizationStore,
		discovery,
	)

	_, err := service.Begin(
		t.Context(),
		BeginAuthorizationInput{
			TenantSlug: "example-company",
			ReturnPath: "/",
		},
	)
	if !errors.Is(
		err,
		ErrFederationUnavailable,
	) {
		t.Fatalf(
			"expected unavailable error, got %v",
			err,
		)
	}

	if authorizationStore.transactionCalls != 0 {
		t.Fatal(
			"failed discovery created a transaction",
		)
	}
}

func TestAuthorizationServiceRejectsInvalidConfiguration(
	t *testing.T,
) {
	authorizationStore := &fakeAuthorizationStore{}
	discovery := &fakeProviderDiscovery{}
	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		30,
	)

	tests := []struct {
		name         string
		store        AuthorizationStore
		discovery    ProviderDiscovery
		secretCipher SecretCipher
		redirectURI  string
	}{
		{
			name:         "missing store",
			discovery:    discovery,
			secretCipher: secretCipher,
			redirectURI:  "https://gatehouse.example.com/callback",
		},
		{
			name:         "missing discovery",
			store:        authorizationStore,
			secretCipher: secretCipher,
			redirectURI:  "https://gatehouse.example.com/callback",
		},
		{
			name:        "missing cipher",
			store:       authorizationStore,
			discovery:   discovery,
			redirectURI: "https://gatehouse.example.com/callback",
		},
		{
			name:         "unsafe redirect URI",
			store:        authorizationStore,
			discovery:    discovery,
			secretCipher: secretCipher,
			redirectURI:  "http://gatehouse.example.com/callback",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAuthorizationService(
				test.store,
				test.discovery,
				test.secretCipher,
				test.redirectURI,
			)
			if !errors.Is(
				err,
				ErrInvalidAuthorizationService,
			) {
				t.Fatalf(
					"expected configuration error, got %v",
					err,
				)
			}
		})
	}

	if _, err := NewAuthorizationService(
		authorizationStore,
		discovery,
		secretCipher,
		"http://localhost:8080/api/v1/auth/federation/callback",
	); err != nil {
		t.Fatalf(
			"localhost development redirect rejected: %v",
			err,
		)
	}
}

var _ AuthorizationStore = (*fakeAuthorizationStore)(nil)
var _ ProviderDiscovery = (*fakeProviderDiscovery)(nil)
var _ SecretCipher = (*AESGCMSecretCipher)(nil)
var _ = pgtype.UUID{}
