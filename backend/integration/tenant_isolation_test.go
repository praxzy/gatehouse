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

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	alphaTenantID    = "00000000-0000-4000-8000-000000000001"
	betaTenantID     = "00000000-0000-4000-8000-000000000002"
	betaMembershipID = "00000000-0000-4000-8000-000000000203"
	betaRoleID       = "00000000-0000-4000-8000-000000000303"
)

func TestTenantScopedQueriesRejectForeignIDs(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	prepareTestDatabase(t, ctx, databaseURL)

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}

	if poolConfig.ConnConfig.Database != "gatehouse_test" {
		t.Fatalf(
			"refusing to run against non-test database %q",
			poolConfig.ConnConfig.Database,
		)
	}

	poolConfig.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(pool.Close)

	loadFixtures(t, ctx, pool)

	queries := store.New(pool)

	t.Run("Alpha cannot load Beta membership", func(t *testing.T) {
		_, err := queries.GetMembershipByID(
			ctx,
			store.GetMembershipByIDParams{
				TenantID:     mustUUID(t, alphaTenantID),
				MembershipID: mustUUID(t, betaMembershipID),
			},
		)

		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})

	t.Run("Alpha cannot load Beta role", func(t *testing.T) {
		_, err := queries.GetRoleByID(
			ctx,
			store.GetRoleByIDParams{
				TenantID: mustUUID(t, alphaTenantID),
				RoleID:   mustUUID(t, betaRoleID),
			},
		)

		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})

	t.Run("Beta can load its own membership and role", func(t *testing.T) {
		if _, err := queries.GetMembershipByID(
			ctx,
			store.GetMembershipByIDParams{
				TenantID:     mustUUID(t, betaTenantID),
				MembershipID: mustUUID(t, betaMembershipID),
			},
		); err != nil {
			t.Fatalf("load Beta membership: %v", err)
		}

		if _, err := queries.GetRoleByID(
			ctx,
			store.GetRoleByIDParams{
				TenantID: mustUUID(t, betaTenantID),
				RoleID:   mustUUID(t, betaRoleID),
			},
		); err != nil {
			t.Fatalf("load Beta role: %v", err)
		}
	})
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