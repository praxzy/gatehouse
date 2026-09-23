package integration_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

func TestUpstreamSessionCanCompleteMFA(
	t *testing.T,
) {
	ctx := context.Background()
	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	registration, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Federated MFA Company",
			TenantSlug:  "federated-mfa-company",
			Email:       "owner@federated-mfa.test",
			DisplayName: "Federated Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register federated user: %v", err)
	}

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	_, err = pool.Exec(
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

	secret := bytes.Repeat([]byte{0x35}, 20)
	challengeTime := time.Now()

	code, err := auth.GenerateTOTPCode(
		secret,
		challengeTime,
	)
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	acceptedStep, matches := auth.MatchTOTPCode(
		secret,
		code,
		challengeTime,
	)
	if !matches {
		t.Fatal("generated TOTP code did not match")
	}

	encryptedSecret, err :=
		newIntegrationMFASecretCipher(t).Encrypt(
			registration.UserID,
			secret,
		)
	if err != nil {
		t.Fatalf("encrypt TOTP secret: %v", err)
	}

	_, err = pool.Exec(
		ctx,
		`
			INSERT INTO totp_credentials (
				user_id,
				secret_ciphertext,
				secret_nonce,
				encryption_key_id,
				status,
				last_accepted_timestep,
				confirmed_at
			)
			VALUES ($1, $2, $3, $4, 'active', $5, now())
		`,
		registration.UserID,
		encryptedSecret.Ciphertext,
		encryptedSecret.Nonce,
		encryptedSecret.KeyID,
		acceptedStep-1,
	)
	if err != nil {
		t.Fatalf("create active TOTP credential: %v", err)
	}

	var connectionID pgtype.UUID
	err = pool.QueryRow(
		ctx,
		`
			INSERT INTO upstream_oidc_connections (
				tenant_id,
				display_name,
				issuer,
				client_id,
				client_secret_ciphertext,
				client_secret_nonce,
				encryption_key_id
			)
			VALUES (
				$1,
				'Company SSO',
				'https://identity.example.com',
				'gatehouse-client',
				$2,
				$3,
				'test-federation-v1'
			)
			RETURNING id
		`,
		registration.TenantID,
		bytes.Repeat([]byte{0x61}, 32),
		bytes.Repeat([]byte{0x62}, 12),
	).Scan(&connectionID)
	if err != nil {
		t.Fatalf("create upstream connection: %v", err)
	}

	const upstreamSubject = "external-owner-123"

	_, err = pool.Exec(
		ctx,
		`
			INSERT INTO upstream_oidc_identities (
				tenant_id,
				connection_id,
				subject,
				membership_id
			)
			VALUES ($1, $2, $3, $4)
		`,
		registration.TenantID,
		connectionID,
		upstreamSubject,
		registration.MembershipID,
	)
	if err != nil {
		t.Fatalf("map upstream identity: %v", err)
	}

	upstreamSession, err :=
		authentication.CreateUpstreamSession(
			ctx,
			auth.CreateUpstreamSessionInput{
				TenantID:     registration.TenantID,
				ConnectionID: connectionID,
				Subject:      upstreamSubject,
			},
		)
	if err != nil {
		t.Fatalf("create upstream session: %v", err)
	}

	initialSession, err :=
		authentication.ResolveSession(
			ctx,
			upstreamSession.Token,
		)
	if err != nil {
		t.Fatalf("resolve upstream session: %v", err)
	}

	if initialSession.AuthenticationLevel != "upstream" ||
		!initialSession.MFARequired ||
		!initialSession.MFAEnrolled {
		t.Fatalf(
			"unexpected upstream session state: %+v",
			initialSession,
		)
	}

	challenge, err :=
		authentication.CompleteMFAWithTOTP(
			ctx,
			initialSession,
			code,
		)
	if err != nil {
		t.Fatalf(
			"complete MFA from upstream session: %v",
			err,
		)
	}

	if challenge.Session.Token ==
		upstreamSession.Token {
		t.Fatal("MFA did not rotate the upstream session")
	}

	_, err = authentication.ResolveSession(
		ctx,
		upstreamSession.Token,
	)
	if !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf(
			"expected upstream session revocation, got %v",
			err,
		)
	}

	elevatedSession, err :=
		authentication.ResolveSession(
			ctx,
			challenge.Session.Token,
		)
	if err != nil {
		t.Fatalf("resolve MFA session: %v", err)
	}

	if elevatedSession.AuthenticationLevel != "mfa" ||
		!elevatedSession.MFARequired ||
		!elevatedSession.MFAEnrolled {
		t.Fatalf(
			"unexpected elevated session state: %+v",
			elevatedSession,
		)
	}
}
