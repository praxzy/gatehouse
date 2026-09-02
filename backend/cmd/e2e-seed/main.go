package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/application"
	"github.com/praxzy/gatehouse/backend/internal/auth"
)

const (
	e2ePassword = "correct horse battery staple"

	employeePortalClientID = "ghc_e2e_employee_portal_client_00001"

	employeePortalClientSecret = "ghs_e2e_employee_portal_secret_0000000000000000"

	tenantID = "15000000-0000-4000-8000-000000000001"

	reserveOwnerUserID       = "15000000-0000-4000-8000-000000000002"
	aliceUserID              = "15000000-0000-4000-8000-000000000003"
	bobUserID                = "15000000-0000-4000-8000-000000000004"
	reserveOwnerMembershipID = "15000000-0000-4000-8000-000000000005"
	aliceMembershipID        = "15000000-0000-4000-8000-000000000006"
	bobMembershipID          = "15000000-0000-4000-8000-000000000007"

	ownerRoleID  = "15000000-0000-4000-8000-000000000008"
	memberRoleID = "15000000-0000-4000-8000-000000000009"
	adminRoleID  = "15000000-0000-4000-8000-000000000010"
	viewerRoleID = "15000000-0000-4000-8000-000000000011"

	employeePortalApplicationID = "15000000-0000-4000-8000-000000000012"

	employeePortalRedirectURI = "http://localhost:8090/oauth/callback"
)

type statement struct {
	name  string
	query string
	args  []any
}

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	passwordHash, err := auth.HashPassword(e2ePassword)
	if err != nil {
		return fmt.Errorf("hash E2E password: %w", err)
	}

	clientSecretHash := application.HashClientSecret(
		employeePortalClientSecret,
	)

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	transaction, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin seed transaction: %w", err)
	}
	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	statements := []statement{
		{
			name: "tenant",
			query: `
				INSERT INTO tenants (id, name, slug, status)
				VALUES ($1, 'Northstar', 'northstar', 'active')
			`,
			args: []any{tenantID},
		},
		{
			name: "users",
			query: `
				INSERT INTO users (
					id,
					email,
					display_name,
					status,
					email_verified_at
				)
				VALUES
					($1, 'owner@northstar.test', 'Reserve Owner', 'active', now()),
					($2, 'alice@northstar.test', 'Alice Admin', 'active', now()),
					($3, 'bob@northstar.test', 'Bob Viewer', 'active', now())
			`,
			args: []any{
				reserveOwnerUserID,
				aliceUserID,
				bobUserID,
			},
		},
		{
			name: "password credentials",
			query: `
				INSERT INTO password_credentials (
					user_id,
					password_hash
				)
				VALUES
					($1, $4),
					($2, $4),
					($3, $4)
			`,
			args: []any{
				reserveOwnerUserID,
				aliceUserID,
				bobUserID,
				passwordHash,
			},
		},
		{
			name: "memberships",
			query: `
				INSERT INTO memberships (
					id,
					tenant_id,
					user_id,
					status
				)
				VALUES
					($1, $4, $5, 'active'),
					($2, $4, $6, 'active'),
					($3, $4, $7, 'active')
			`,
			args: []any{
				reserveOwnerMembershipID,
				aliceMembershipID,
				bobMembershipID,
				tenantID,
				reserveOwnerUserID,
				aliceUserID,
				bobUserID,
			},
		},
		{
			name: "roles",
			query: `
				INSERT INTO roles (
					id,
					tenant_id,
					role_key,
					name,
					description,
					is_system
				)
				VALUES
					($1, $5, 'owner', 'Owner', 'Full organization access.', true),
					($2, $5, 'member', 'Member', 'Standard organization member.', true),
					($3, $5, NULL, 'Admin', 'Administers the employee portal.', false),
					($4, $5, NULL, 'Viewer', 'Basic employee portal membership.', false)
			`,
			args: []any{
				ownerRoleID,
				memberRoleID,
				adminRoleID,
				viewerRoleID,
				tenantID,
			},
		},
		{
			name: "owner permissions",
			query: `
				INSERT INTO role_permissions (
					tenant_id,
					role_id,
					permission
				)
				SELECT $1, $2, permission
				FROM permission_catalog
			`,
			args: []any{tenantID, ownerRoleID},
		},
		{
			name: "admin permissions",
			query: `
				INSERT INTO role_permissions (
					tenant_id,
					role_id,
					permission
				)
				SELECT $1, $2, permission
				FROM permission_catalog
			`,
			args: []any{tenantID, adminRoleID},
		},
		{
			name: "member permissions",
			query: `
				INSERT INTO role_permissions (
					tenant_id,
					role_id,
					permission
				)
				SELECT $1, $2, permission
				FROM permission_catalog
				WHERE permission IN (
					'tenant.read',
					'member.read'
				)
			`,
			args: []any{tenantID, memberRoleID},
		},
		{
			name: "viewer permissions",
			query: `
				INSERT INTO role_permissions (
					tenant_id,
					role_id,
					permission
				)
				SELECT $1, $2, permission
				FROM permission_catalog
				WHERE permission = 'tenant.read'
			`,
			args: []any{tenantID, viewerRoleID},
		},
		{
			name: "membership roles",
			query: `
				INSERT INTO membership_roles (
					tenant_id,
					membership_id,
					role_id
				)
				VALUES
					($1, $2, $5),
					($1, $3, $6),
					($1, $4, $7)
			`,
			args: []any{
				tenantID,
				reserveOwnerMembershipID,
				aliceMembershipID,
				bobMembershipID,
				ownerRoleID,
				adminRoleID,
				viewerRoleID,
			},
		},
		{
			name: "employee portal application",
			query: `
				INSERT INTO applications (
					id,
					tenant_id,
					name,
					description,
					client_id,
					client_type,
					client_secret_hash,
					client_secret_created_at,
					status,
					access_mode
				)
				VALUES (
					$1,
					$2,
					'Employee Portal',
					'Day 15 browser E2E relying party.',
					$3,
					'confidential',
					$4,
					now(),
					'active',
					'allowed_roles'
				)
			`,
			args: []any{
				employeePortalApplicationID,
				tenantID,
				employeePortalClientID,
				clientSecretHash,
			},
		},
		{
			name: "employee portal redirect URI",
			query: `
				INSERT INTO redirect_uris (
					tenant_id,
					application_id,
					uri
				)
				VALUES ($1, $2, $3)
			`,
			args: []any{
				tenantID,
				employeePortalApplicationID,
				employeePortalRedirectURI,
			},
		},
		{
			name: "employee portal access policy",
			query: `
				INSERT INTO application_access (
					tenant_id,
					application_id,
					role_id
				)
				VALUES ($1, $2, $3)
			`,
			args: []any{
				tenantID,
				employeePortalApplicationID,
				adminRoleID,
			},
		},
	}

	for _, item := range statements {
		if _, err := transaction.Exec(
			ctx,
			item.query,
			item.args...,
		); err != nil {
			return fmt.Errorf("seed %s: %w", item.name, err)
		}
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("commit E2E seed: %w", err)
	}

	log.Print("E2E fixture seeded")
	return nil
}
