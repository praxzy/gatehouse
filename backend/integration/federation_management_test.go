package integration_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/federation"
)

type staticFederationDiscovery struct {
	document federation.DiscoveryDocument
	err      error
	issuer   string
	calls    int
}

func (fake *staticFederationDiscovery) Discover(
	_ context.Context,
	issuer string,
) (federation.DiscoveryDocument, error) {
	fake.calls++
	fake.issuer = issuer

	return fake.document, fake.err
}

func TestFederationManagementLifecycle(
	t *testing.T,
) {
	ctx := context.Background()
	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Federation Company",
			TenantSlug:  "federation-company",
			Email:       "owner@federation.test",
			DisplayName: "Federation Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register federation tenant: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	otherRegistration, err :=
		authentication.Register(
			ctx,
			auth.RegisterInput{
				TenantName:  "Other Company",
				TenantSlug:  "other-federation-company",
				Email:       "owner@other-federation.test",
				DisplayName: "Other Owner",
				Password:    "correct horse battery staple",
			},
		)
	if err != nil {
		t.Fatalf("register other tenant: %v", err)
	}

	const issuer = "https://identity.example.com"

	discovery := &staticFederationDiscovery{
		document: federation.DiscoveryDocument{
			Issuer: issuer,
		},
	}

	secretCipher, err :=
		federation.NewAESGCMSecretCipher(
			"integration-federation-v1",
			bytes.Repeat([]byte{0x71}, 32),
		)
	if err != nil {
		t.Fatalf(
			"create federation secret cipher: %v",
			err,
		)
	}

	service, err :=
		federation.NewManagementService(
			pool,
			discovery,
			secretCipher,
			audit.NewWriter(),
		)
	if err != nil {
		t.Fatalf(
			"create federation management service: %v",
			err,
		)
	}

	session := auth.SessionContext{
		TenantID:     registration.TenantID,
		MembershipID: registration.MembershipID,
		UserID:       registration.UserID,
		Permissions: []string{
			auth.PermissionFederationManage,
		},
	}

	const clientSecret = "super-secret-client-value"

	connection, err := service.SaveConnection(
		ctx,
		session,
		federation.SaveConnectionInput{
			DisplayName:  "Company SSO",
			Issuer:       issuer,
			ClientID:     "gatehouse-federation-client",
			ClientSecret: clientSecret,
		},
	)
	if err != nil {
		t.Fatalf(
			"save federation connection: %v",
			err,
		)
	}

	if !connection.ConnectionID.Valid ||
		connection.DisplayName != "Company SSO" ||
		connection.Issuer != issuer ||
		connection.ClientID !=
			"gatehouse-federation-client" ||
		connection.Status !=
			federation.ConnectionStatusEnabled {
		t.Fatalf(
			"unexpected connection: %+v",
			connection,
		)
	}

	if discovery.calls != 1 ||
		discovery.issuer != issuer {
		t.Fatalf(
			"unexpected discovery call: %+v",
			discovery,
		)
	}

	var ciphertext []byte
	var nonce []byte
	var keyID string

	err = pool.QueryRow(
		ctx,
		`
			SELECT
				client_secret_ciphertext,
				client_secret_nonce,
				encryption_key_id
			FROM upstream_oidc_connections
			WHERE tenant_id = $1
		`,
		registration.TenantID,
	).Scan(
		&ciphertext,
		&nonce,
		&keyID,
	)
	if err != nil {
		t.Fatalf(
			"load stored client secret: %v",
			err,
		)
	}

	if bytes.Equal(
		ciphertext,
		[]byte(clientSecret),
	) ||
		bytes.Contains(
			ciphertext,
			[]byte(clientSecret),
		) {
		t.Fatal(
			"database exposed plaintext client secret",
		)
	}

	decrypted, err := secretCipher.Decrypt(
		registration.TenantID,
		federation.SecretPurposeClientSecret,
		federation.EncryptedSecret{
			Ciphertext: ciphertext,
			Nonce:      nonce,
			KeyID:      keyID,
		},
	)
	if err != nil {
		t.Fatalf(
			"decrypt stored client secret: %v",
			err,
		)
	}
	defer clear(decrypted)

	if string(decrypted) != clientSecret {
		t.Fatal(
			"stored client secret did not decrypt correctly",
		)
	}

	loadedConnection, err :=
		service.GetConnection(ctx, session)
	if err != nil {
		t.Fatalf(
			"get federation connection: %v",
			err,
		)
	}

	if loadedConnection != connection {
		t.Fatalf(
			"loaded connection differs: %+v",
			loadedConnection,
		)
	}

	disabledConnection, err :=
		service.SetConnectionStatus(
			ctx,
			session,
			federation.ConnectionStatusDisabled,
		)
	if err != nil {
		t.Fatalf(
			"disable federation connection: %v",
			err,
		)
	}

	if disabledConnection.Status !=
		federation.ConnectionStatusDisabled {
		t.Fatalf(
			"expected disabled connection, got %q",
			disabledConnection.Status,
		)
	}

	_, err = service.CreateIdentityMapping(
		ctx,
		session,
		federation.CreateIdentityMappingInput{
			Subject:      "foreign-tenant-subject",
			MembershipID: otherRegistration.MembershipID,
		},
	)
	if !errors.Is(
		err,
		federation.
			ErrIdentityMappingTargetNotFound,
	) {
		t.Fatalf(
			"expected foreign membership rejection, got %v",
			err,
		)
	}

	const upstreamSubject = "external-owner-123"

	createdMapping, err :=
		service.CreateIdentityMapping(
			ctx,
			session,
			federation.CreateIdentityMappingInput{
				Subject:      upstreamSubject,
				MembershipID: registration.MembershipID,
			},
		)
	if err != nil {
		t.Fatalf(
			"create identity mapping: %v",
			err,
		)
	}

	if createdMapping.Subject !=
		upstreamSubject ||
		createdMapping.MembershipID !=
			registration.MembershipID {
		t.Fatalf(
			"unexpected created mapping: %+v",
			createdMapping,
		)
	}

	mappings, err :=
		service.ListIdentityMappings(
			ctx,
			session,
		)
	if err != nil {
		t.Fatalf(
			"list identity mappings: %v",
			err,
		)
	}

	if len(mappings) != 1 {
		t.Fatalf(
			"expected one mapping, got %d",
			len(mappings),
		)
	}

	mapping := mappings[0]
	if mapping.Subject != upstreamSubject ||
		mapping.MembershipID !=
			registration.MembershipID ||
		mapping.UserID != registration.UserID ||
		mapping.Email !=
			"owner@federation.test" ||
		mapping.DisplayName !=
			"Federation Owner" ||
		mapping.MembershipStatus != "active" {
		t.Fatalf(
			"unexpected mapping: %+v",
			mapping,
		)
	}

	err = service.DeleteIdentityMapping(
		ctx,
		session,
		federation.DeleteIdentityMappingInput{
			Subject: upstreamSubject,
		},
	)
	if err != nil {
		t.Fatalf(
			"delete identity mapping: %v",
			err,
		)
	}

	mappings, err =
		service.ListIdentityMappings(
			ctx,
			session,
		)
	if err != nil {
		t.Fatalf(
			"list mappings after deletion: %v",
			err,
		)
	}
	if len(mappings) != 0 {
		t.Fatalf(
			"expected no mappings, got %d",
			len(mappings),
		)
	}

	forbiddenSession := session
	forbiddenSession.Permissions = nil

	_, err = service.GetConnection(
		ctx,
		forbiddenSession,
	)
	if !errors.Is(
		err,
		federation.
			ErrFederationManagementForbidden,
	) {
		t.Fatalf(
			"expected management denial, got %v",
			err,
		)
	}

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND event_type LIKE 'federation.%'
		`,
		4,
		registration.TenantID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND metadata::text LIKE '%' || $2 || '%'
		`,
		0,
		registration.TenantID,
		clientSecret,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM audit_events
			WHERE tenant_id = $1
			  AND metadata::text LIKE '%' || $2 || '%'
		`,
		0,
		registration.TenantID,
		upstreamSubject,
	)
}
