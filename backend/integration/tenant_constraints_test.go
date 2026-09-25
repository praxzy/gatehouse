package integration_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestTenantForeignKeyConstraintsRejectMixedTenantIDs(
	t *testing.T,
) {
	fixture := newSecurityIntegrationFixture(t)

	t.Run(
		"membership cannot reference a foreign tenant role",
		func(t *testing.T) {
			_, err := fixture.Pool.Exec(
				fixture.Context,
				`
					INSERT INTO membership_roles (
						tenant_id,
						membership_id,
						role_id
					)
					VALUES ($1, $2, $3)
				`,
				fixture.Alpha.ID,
				fixture.Alpha.Admin.MembershipID,
				fixture.Beta.Admin.RoleID,
			)

			requireForeignKeyViolation(
				t,
				err,
				"membership_roles_role_fk",
			)

			assertDatabaseCount(
				t,
				fixture.Context,
				fixture.Pool,
				`
					SELECT count(*)
					FROM membership_roles
					WHERE tenant_id = $1
					  AND membership_id = $2
					  AND role_id = $3
				`,
				0,
				fixture.Alpha.ID,
				fixture.Alpha.Admin.MembershipID,
				fixture.Beta.Admin.RoleID,
			)
		},
	)

	t.Run(
		"application cannot allow a foreign tenant role",
		func(t *testing.T) {
			_, err := fixture.Pool.Exec(
				fixture.Context,
				`
					INSERT INTO application_access (
						tenant_id,
						application_id,
						role_id
					)
					VALUES ($1, $2, $3)
				`,
				fixture.Alpha.ID,
				fixture.Alpha.Application.ID,
				fixture.Beta.Admin.RoleID,
			)

			requireForeignKeyViolation(
				t,
				err,
				"application_access_role_fk",
			)

			assertDatabaseCount(
				t,
				fixture.Context,
				fixture.Pool,
				`
					SELECT count(*)
					FROM application_access
					WHERE tenant_id = $1
					  AND application_id = $2
					  AND role_id = $3
				`,
				0,
				fixture.Alpha.ID,
				fixture.Alpha.Application.ID,
				fixture.Beta.Admin.RoleID,
			)
		},
	)

	t.Run(
		"redirect URI cannot reference a foreign tenant application",
		func(t *testing.T) {
			redirectID := mustUUID(
				t,
				"00000000-0000-4000-8000-000000000599",
			)

			_, err := fixture.Pool.Exec(
				fixture.Context,
				`
					INSERT INTO redirect_uris (
						id,
						tenant_id,
						application_id,
						uri
					)
					VALUES ($1, $2, $3, $4)
				`,
				redirectID,
				fixture.Alpha.ID,
				fixture.Beta.Application.ID,
				"https://forged.example.test/callback",
			)

			requireForeignKeyViolation(
				t,
				err,
				"redirect_uris_application_fk",
			)

			assertDatabaseCount(
				t,
				fixture.Context,
				fixture.Pool,
				`
					SELECT count(*)
					FROM redirect_uris
					WHERE id = $1
				`,
				0,
				redirectID,
			)
		},
	)
}

func requireForeignKeyViolation(
	t *testing.T,
	err error,
	expectedConstraint string,
) {
	t.Helper()

	if err == nil {
		t.Fatal("expected foreign-key violation")
	}

	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		t.Fatalf(
			"expected PostgreSQL error, got %T: %v",
			err,
			err,
		)
	}

	if postgresError.Code != "23503" {
		t.Fatalf(
			"expected SQLSTATE 23503, got %q: %v",
			postgresError.Code,
			err,
		)
	}

	if postgresError.ConstraintName != expectedConstraint {
		t.Fatalf(
			"expected constraint %q, got %q",
			expectedConstraint,
			postgresError.ConstraintName,
		)
	}
}
