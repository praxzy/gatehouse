package integration_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type discardEmailVerificationSender struct{}

func (discardEmailVerificationSender) SendEmailVerification(
	_ context.Context,
	_ auth.EmailVerificationDelivery,
) error {
	return nil
}

type discardMembershipInvitationSender struct{}

func (discardMembershipInvitationSender) SendMembershipInvitation(
	_ context.Context,
	_ auth.MembershipInvitationDelivery,
) error {
	return nil
}

func TestRegisterRollsBackOnDuplicateEmailAndTenantSlug(
	t *testing.T,
) {
	ctx := context.Background()
	service, pool := newAuthenticationTestService(t, ctx)

	_, err := service.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Alpha Company",
			TenantSlug:  "alpha-company",
			Email:       "owner@alpha.test",
			DisplayName: "Alpha Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register initial tenant: %v", err)
	}

	assertIdentityTableCounts(t, ctx, pool)

	t.Run("duplicate email rolls back tenant", func(t *testing.T) {
		_, err := service.Register(
			ctx,
			auth.RegisterInput{
				TenantName:  "Email Rollback",
				TenantSlug:  "email-rollback",
				Email:       "owner@alpha.test",
				DisplayName: "Another Owner",
				Password:    "another secure password",
			},
		)

		if !errors.Is(err, auth.ErrEmailAlreadyExists) {
			t.Fatalf(
				"expected ErrEmailAlreadyExists, got %v",
				err,
			)
		}

		assertDatabaseCount(
			t,
			ctx,
			pool,
			`SELECT count(*) FROM tenants WHERE slug = $1`,
			0,
			"email-rollback",
		)

		assertIdentityTableCounts(t, ctx, pool)
	})

	t.Run("duplicate tenant slug does not create user", func(t *testing.T) {
		_, err := service.Register(
			ctx,
			auth.RegisterInput{
				TenantName:  "Duplicate Alpha",
				TenantSlug:  "alpha-company",
				Email:       "new-owner@example.test",
				DisplayName: "New Owner",
				Password:    "another secure password",
			},
		)

		if !errors.Is(err, auth.ErrTenantSlugUnavailable) {
			t.Fatalf(
				"expected ErrTenantSlugUnavailable, got %v",
				err,
			)
		}

		assertDatabaseCount(
			t,
			ctx,
			pool,
			`SELECT count(*) FROM users WHERE email = $1`,
			0,
			"new-owner@example.test",
		)

		assertIdentityTableCounts(t, ctx, pool)
	})
}

func TestRegisterCreatesOwnerIdentityGraph(t *testing.T) {
	ctx := context.Background()
	service, pool := newAuthenticationTestService(t, ctx)

	result, err := service.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Gamma Company",
			TenantSlug:  "gamma-company",
			Email:       "owner@gamma.test",
			DisplayName: "Gamma Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register tenant: %v", err)
	}

	if !result.TenantID.Valid ||
		!result.UserID.Valid ||
		!result.MembershipID.Valid ||
		!result.OwnerRoleID.Valid {
		t.Fatal("expected every registration ID to be valid")
	}

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
		SELECT count(*)
		FROM users
		WHERE id = $1
		  AND email_verified_at IS NULL
	`,
		1,
		result.UserID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
		SELECT count(*)
		FROM email_verification_tokens
		WHERE user_id = $1
		  AND consumed_at IS NULL
		  AND expires_at > now()
	`,
		1,
		result.UserID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM password_credentials
			WHERE user_id = $1
		`,
		1,
		result.UserID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM memberships
			WHERE id = $1
			  AND tenant_id = $2
			  AND user_id = $3
			  AND status = 'active'
		`,
		1,
		result.MembershipID,
		result.TenantID,
		result.UserID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM roles
			WHERE id = $1
			  AND tenant_id = $2
			  AND role_key = 'owner'
			  AND is_system = true
		`,
		1,
		result.OwnerRoleID,
		result.TenantID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM roles
			WHERE tenant_id = $1
			  AND role_key = 'member'
			  AND is_system = true
		`,
		1,
		result.TenantID,
	)

	assertDatabaseCount(
		t,
		ctx,
		pool,
		`
			SELECT count(*)
			FROM membership_roles
			WHERE tenant_id = $1
			  AND membership_id = $2
			  AND role_id = $3
		`,
		1,
		result.TenantID,
		result.MembershipID,
		result.OwnerRoleID,
	)
}

func TestLoginFailureSemantics(t *testing.T) {
	ctx := context.Background()
	service, pool := newAuthenticationTestService(t, ctx)

	registration, err := service.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Login Company",
			TenantSlug:  "login-company",
			Email:       "owner@login.test",
			DisplayName: "Login Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register login user: %v", err)
	}

	_, err = service.Login(
		ctx,
		auth.LoginInput{
			Email:    "owner@login.test",
			Password: "correct horse battery staple",
			ClientIP: "127.0.0.1",
		},
	)
	if !errors.Is(
		err,
		auth.ErrEmailVerificationRequired,
	) {
		t.Fatalf(
			"expected ErrEmailVerificationRequired, got %v",
			err,
		)
	}

	assertInvalidCredentials(
		t,
		service,
		auth.LoginInput{
			Email:    "owner@login.test",
			Password: "wrong password",
			ClientIP: "127.0.0.1",
		},
	)

	markTestEmailVerified(
		t,
		ctx,
		pool,
		registration.UserID,
	)

	login, err := service.Login(
		ctx,
		auth.LoginInput{
			Email:    "owner@login.test",
			Password: "correct horse battery staple",
			ClientIP: "127.0.0.1",
		},
	)
	if err != nil {
		t.Fatalf("login with correct password: %v", err)
	}

	if login.UserID != registration.UserID {
		t.Fatal("login returned the wrong user")
	}

	assertInvalidCredentials(
		t,
		service,
		auth.LoginInput{
			Email:    "owner@login.test",
			Password: "wrong password",
			ClientIP: "127.0.0.1",
		},
	)

	assertInvalidCredentials(
		t,
		service,
		auth.LoginInput{
			Email:    "unknown@login.test",
			Password: "wrong password",
			ClientIP: "127.0.0.1",
		},
	)

	commandTag, err := pool.Exec(
		ctx,
		`
			UPDATE users
			SET status = 'disabled'
			WHERE id = $1
		`,
		registration.UserID,
	)
	if err != nil {
		t.Fatalf("disable user: %v", err)
	}

	if commandTag.RowsAffected() != 1 {
		t.Fatalf(
			"expected one disabled user, affected %d",
			commandTag.RowsAffected(),
		)
	}

	assertInvalidCredentials(
		t,
		service,
		auth.LoginInput{
			Email:    "owner@login.test",
			Password: "correct horse battery staple",
			ClientIP: "127.0.0.1",
		},
	)
}

func newAuthenticationTestService(
	t *testing.T,
	ctx context.Context,
) (*auth.Service, *pgxpool.Pool) {
	t.Helper()

	return newAuthenticationTestServiceWithEmailSender(
		t,
		ctx,
		discardEmailVerificationSender{},
	)
}

func newAuthenticationTestServiceWithEmailSender(
	t *testing.T,
	ctx context.Context,
	sender auth.EmailVerificationSender,
) (*auth.Service, *pgxpool.Pool) {
	t.Helper()

	return newAuthenticationTestServiceWithSenders(
		t,
		ctx,
		sender,
		discardMembershipInvitationSender{},
	)
}

func newAuthenticationTestServiceWithSenders(
	t *testing.T,
	ctx context.Context,
	emailSender auth.EmailVerificationSender,
	invitationSender auth.MembershipInvitationSender,
) (*auth.Service, *pgxpool.Pool) {
	t.Helper()

	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	prepareTestDatabase(t, ctx, databaseURL)

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	limiter, err := auth.NewLocalLoginRateLimiter(
		100,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create login rate limiter: %v", err)
	}

	service, err := auth.NewService(
		pool,
		limiter,
		auth.WithMFASecretCipher(
			newIntegrationMFASecretCipher(t),
		),
		auth.WithEmailVerificationSender(
			emailSender,
		),
		auth.WithMembershipInvitationSender(
			invitationSender,
		),
	)
	if err != nil {
		t.Fatalf("create authentication service: %v", err)
	}

	return service, pool
}

func assertIdentityTableCounts(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
) {
	t.Helper()

	testCases := []struct {
		name  string
		query string
	}{
		{
			name:  "tenants",
			query: `SELECT count(*) FROM tenants`,
		},
		{
			name:  "users",
			query: `SELECT count(*) FROM users`,
		},
		{
			name:  "password credentials",
			query: `SELECT count(*) FROM password_credentials`,
		},
		{
			name:  "memberships",
			query: `SELECT count(*) FROM memberships`,
		},
		{
			name:  "roles",
			query: `SELECT count(*) FROM roles`,
		},
		{
			name:  "membership roles",
			query: `SELECT count(*) FROM membership_roles`,
		},
		{
			name:  "email verification tokens",
			query: `SELECT count(*) FROM email_verification_tokens`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			expected := int64(1)
			if testCase.name == "roles" {
				expected = 2
			}

			assertDatabaseCount(
				t,
				ctx,
				pool,
				testCase.query,
				expected,
			)
		})
	}
}

func assertDatabaseCount(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	query string,
	expected int64,
	arguments ...any,
) {
	t.Helper()

	var actual int64
	if err := pool.QueryRow(
		ctx,
		query,
		arguments...,
	).Scan(&actual); err != nil {
		t.Fatalf("query database count: %v", err)
	}

	if actual != expected {
		t.Fatalf(
			"expected database count %d, got %d",
			expected,
			actual,
		)
	}
}

func assertInvalidCredentials(
	t *testing.T,
	service *auth.Service,
	input auth.LoginInput,
) {
	t.Helper()

	_, err := service.Login(context.Background(), input)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf(
			"expected ErrInvalidCredentials, got %v",
			err,
		)
	}
}

func markTestEmailVerified(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	userID pgtype.UUID,
) {
	t.Helper()

	commandTag, err := pool.Exec(
		ctx,
		`
			UPDATE users
			SET
				email_verified_at = now(),
				updated_at = now()
			WHERE id = $1
			  AND email_verified_at IS NULL
		`,
		userID,
	)
	if err != nil {
		t.Fatalf("mark test email verified: %v", err)
	}

	if commandTag.RowsAffected() != 1 {
		t.Fatalf(
			"expected one verified test user, affected %d",
			commandTag.RowsAffected(),
		)
	}
}
