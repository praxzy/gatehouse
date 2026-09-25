package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/praxzy/gatehouse/backend/internal/application"
	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

func TestTenantScopedQueriesRejectForeignIDs(t *testing.T) {
	fixture := newSecurityIntegrationFixture(t)

	ctx := fixture.Context
	queries := fixture.Queries

	t.Run(
		"Alpha cannot load Beta membership",
		func(t *testing.T) {
			_, err := queries.GetMembershipByID(
				ctx,
				store.GetMembershipByIDParams{
					TenantID: fixture.Alpha.ID,
					MembershipID: fixture.Beta.
						Admin.MembershipID,
				},
			)

			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf(
					"expected pgx.ErrNoRows, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"Alpha cannot load Beta role",
		func(t *testing.T) {
			_, err := queries.GetRoleByID(
				ctx,
				store.GetRoleByIDParams{
					TenantID: fixture.Alpha.ID,
					RoleID: fixture.Beta.
						Admin.RoleID,
				},
			)

			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf(
					"expected pgx.ErrNoRows, got %v",
					err,
				)
			}
		},
	)

	applications, err := application.NewService(
		fixture.Pool,
		audit.NewWriter(),
	)
	if err != nil {
		t.Fatalf(
			"create application service: %v",
			err,
		)
	}

	alphaSession := auth.SessionContext{
		TenantID:     fixture.Alpha.ID,
		UserID:       fixture.Alpha.Admin.UserID,
		MembershipID: fixture.Alpha.Admin.MembershipID,
		Permissions: []string{
			auth.PermissionApplicationRead,
		},
	}

	t.Run(
		"Alpha user cannot request Beta application",
		func(t *testing.T) {
			_, err := applications.GetApplication(
				ctx,
				alphaSession,
				fixture.Beta.Application.ID,
			)

			if !errors.Is(
				err,
				application.ErrApplicationNotFound,
			) {
				t.Fatalf(
					"expected application not found, got %v",
					err,
				)
			}
		},
	)

	t.Run(
		"Alpha lists only Alpha applications",
		func(t *testing.T) {
			items, err := applications.ListApplications(
				ctx,
				alphaSession,
			)
			if err != nil {
				t.Fatalf(
					"list Alpha applications: %v",
					err,
				)
			}

			if len(items) != 1 {
				t.Fatalf(
					"expected one Alpha application, got %d",
					len(items),
				)
			}

			if items[0].ApplicationID !=
				fixture.Alpha.Application.ID {
				t.Fatalf(
					"Alpha list exposed application %v",
					items[0].ApplicationID,
				)
			}
		},
	)

	t.Run(
		"Beta can load its own resources",
		func(t *testing.T) {
			if _, err := queries.GetMembershipByID(
				ctx,
				store.GetMembershipByIDParams{
					TenantID: fixture.Beta.ID,
					MembershipID: fixture.Beta.
						Admin.MembershipID,
				},
			); err != nil {
				t.Fatalf(
					"load Beta membership: %v",
					err,
				)
			}

			if _, err := queries.GetRoleByID(
				ctx,
				store.GetRoleByIDParams{
					TenantID: fixture.Beta.ID,
					RoleID: fixture.Beta.
						Admin.RoleID,
				},
			); err != nil {
				t.Fatalf(
					"load Beta role: %v",
					err,
				)
			}
		},
	)
}

func prepareTestDatabase(
	t *testing.T,
	ctx context.Context,
	databaseURL string,
) {
	t.Helper()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}

	if config.ConnConfig.Database != "gatehouse_test" {
		t.Fatalf(
			"refusing to reset non-test database %q",
			config.ConnConfig.Database,
		)
	}

	database, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open migration connection: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})

	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	if _, err := database.ExecContext(ctx, "DROP SCHEMA public CASCADE"); err != nil {
		t.Fatalf("drop test schema: %v", err)
	}

	if _, err := database.ExecContext(ctx, "CREATE SCHEMA public"); err != nil {
		t.Fatalf("create test schema: %v", err)
	}

	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set Goose dialect: %v", err)
	}

	if err := goose.Up(database, migrationsDirectory(t)); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
}

func loadFixtures(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) {
	t.Helper()

	fixtures, err := os.ReadFile(
		filepath.Join(projectDirectory(t), "integration", "testdata", "identity_fixtures.sql"),
	)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}

	if _, err := pool.Exec(ctx, string(fixtures)); err != nil {
		t.Fatalf("load fixtures: %v", err)
	}
}

func migrationsDirectory(t *testing.T) string {
	t.Helper()
	return filepath.Join(projectDirectory(t), "migrations")
}

func projectDirectory(t *testing.T) string {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("determine integration test location")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), ".."))
}

func mustUUID(t *testing.T, value string) pgtype.UUID {
	t.Helper()

	var id pgtype.UUID
	if err := id.Scan(value); err != nil {
		t.Fatalf("parse UUID %q: %v", value, err)
	}

	return id
}
