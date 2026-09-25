package integration_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	fixtureAlphaTenantID = "00000000-0000-4000-8000-000000000001"
	fixtureBetaTenantID  = "00000000-0000-4000-8000-000000000002"

	fixtureAliceUserID = "00000000-0000-4000-8000-000000000101"
	fixtureBobUserID   = "00000000-0000-4000-8000-000000000102"
	fixtureCarolUserID = "00000000-0000-4000-8000-000000000103"

	fixtureAliceMembershipID = "00000000-0000-4000-8000-000000000201"
	fixtureBobMembershipID   = "00000000-0000-4000-8000-000000000202"
	fixtureCarolMembershipID = "00000000-0000-4000-8000-000000000203"

	fixtureAlphaAdminRoleID  = "00000000-0000-4000-8000-000000000301"
	fixtureAlphaViewerRoleID = "00000000-0000-4000-8000-000000000302"
	fixtureBetaAdminRoleID   = "00000000-0000-4000-8000-000000000303"

	fixtureAlphaApplicationID = "00000000-0000-4000-8000-000000000401"
	fixtureBetaApplicationID  = "00000000-0000-4000-8000-000000000402"

	fixtureAlphaClientID = "ghc_alpha000000000000000000000000000"
	fixtureBetaClientID  = "ghc_beta0000000000000000000000000000"

	fixtureAlphaRedirectURI = "https://alpha.example.test/oauth/callback"
	fixtureBetaRedirectURI  = "https://beta.example.test/oauth/callback"
)

type fixtureMember struct {
	UserID       pgtype.UUID
	MembershipID pgtype.UUID
	RoleID       pgtype.UUID
}

type fixtureApplication struct {
	ID          pgtype.UUID
	ClientID    string
	RedirectURI string
}

type fixtureTenant struct {
	ID          pgtype.UUID
	Slug        string
	Admin       fixtureMember
	Viewer      fixtureMember
	Application fixtureApplication
}

type securityIntegrationFixture struct {
	Context        context.Context
	Pool           *pgxpool.Pool
	Queries        *store.Queries
	Authentication *auth.Service

	Alpha fixtureTenant
	Beta  fixtureTenant
}

func newSecurityIntegrationFixture(
	t *testing.T,
) *securityIntegrationFixture {
	t.Helper()

	ctx := context.Background()

	authentication, pool :=
		newAuthenticationTestService(t, ctx)

	loadFixtures(t, ctx, pool)

	return &securityIntegrationFixture{
		Context:        ctx,
		Pool:           pool,
		Queries:        store.New(pool),
		Authentication: authentication,

		Alpha: fixtureTenant{
			ID:   mustUUID(t, fixtureAlphaTenantID),
			Slug: "alpha",
			Admin: fixtureMember{
				UserID: mustUUID(
					t,
					fixtureAliceUserID,
				),
				MembershipID: mustUUID(
					t,
					fixtureAliceMembershipID,
				),
				RoleID: mustUUID(
					t,
					fixtureAlphaAdminRoleID,
				),
			},
			Viewer: fixtureMember{
				UserID: mustUUID(
					t,
					fixtureBobUserID,
				),
				MembershipID: mustUUID(
					t,
					fixtureBobMembershipID,
				),
				RoleID: mustUUID(
					t,
					fixtureAlphaViewerRoleID,
				),
			},
			Application: fixtureApplication{
				ID: mustUUID(
					t,
					fixtureAlphaApplicationID,
				),
				ClientID:    fixtureAlphaClientID,
				RedirectURI: fixtureAlphaRedirectURI,
			},
		},

		Beta: fixtureTenant{
			ID:   mustUUID(t, fixtureBetaTenantID),
			Slug: "beta",
			Admin: fixtureMember{
				UserID: mustUUID(
					t,
					fixtureCarolUserID,
				),
				MembershipID: mustUUID(
					t,
					fixtureCarolMembershipID,
				),
				RoleID: mustUUID(
					t,
					fixtureBetaAdminRoleID,
				),
			},
			Application: fixtureApplication{
				ID: mustUUID(
					t,
					fixtureBetaApplicationID,
				),
				ClientID:    fixtureBetaClientID,
				RedirectURI: fixtureBetaRedirectURI,
			},
		},
	}
}
