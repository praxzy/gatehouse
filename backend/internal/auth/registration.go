package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	minPasswordLength = 12
	maxPasswordLength = 1024
	maxEmailLength    = 254
	maxNameLength     = 200
)

var (
	ErrInvalidRegistration   = errors.New("invalid registration")
	ErrEmailAlreadyExists    = errors.New("email is already registered")
	ErrTenantSlugUnavailable = errors.New("tenant slug is unavailable")
)

var tenantSlugPattern = regexp.MustCompile(
	`^[a-z0-9]+(?:-[a-z0-9]+)*$`,
)

type RegisterInput struct {
	TenantName  string
	TenantSlug  string
	Email       string
	DisplayName string
	Password    string
}

type RegisterResult struct {
	TenantID     pgtype.UUID
	UserID       pgtype.UUID
	MembershipID pgtype.UUID
	OwnerRoleID  pgtype.UUID
}

func (service *Service) Register(
	ctx context.Context,
	input RegisterInput,
) (RegisterResult, error) {
	normalized, err := normalizeRegistration(input)
	if err != nil {
		return RegisterResult{}, err
	}

	passwordHash, err := HashPassword(normalized.Password)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("hash password: %w", err)
	}

	verificationToken, verificationHash, err := generateEmailVerificationToken()
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"generate email verification token: %w",
			err,
		)
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"begin registration transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	tenant, err := queries.CreateTenant(
		ctx,
		store.CreateTenantParams{
			Name: normalized.TenantName,
			Slug: normalized.TenantSlug,
		},
	)
	if err != nil {
		return RegisterResult{}, mapRegistrationError(
			"create tenant",
			err,
		)
	}

	user, err := queries.CreateUser(
		ctx,
		store.CreateUserParams{
			Email:       normalized.Email,
			DisplayName: normalized.DisplayName,
		},
	)
	if err != nil {
		return RegisterResult{}, mapRegistrationError(
			"create user",
			err,
		)
	}

	err = queries.CreatePasswordCredential(
		ctx,
		store.CreatePasswordCredentialParams{
			UserID:       user.ID,
			PasswordHash: passwordHash,
		},
	)
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"create password credential: %w",
			err,
		)
	}

	storedVerification, err :=
		queries.UpsertEmailVerificationToken(
			ctx,
			store.UpsertEmailVerificationTokenParams{
				UserID:          user.ID,
				TokenHash:       verificationHash,
				LifetimeSeconds: emailVerificationLifetimeSeconds,
			},
		)
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"store email verification token: %w",
			err,
		)
	}

	if !storedVerification.ExpiresAt.Valid {
		return RegisterResult{}, errors.New(
			"stored email verification has no expiration",
		)
	}

	membership, err := queries.CreateOwnerMembership(
		ctx,
		store.CreateOwnerMembershipParams{
			TenantID: tenant.ID,
			UserID:   user.ID,
		},
	)
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"create owner membership: %w",
			err,
		)
	}

	ownerRole, err := queries.CreateOwnerRole(ctx, tenant.ID)
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"create owner role: %w",
			err,
		)
	}

	err = queries.AssignRoleToMembership(
		ctx,
		store.AssignRoleToMembershipParams{
			TenantID:     tenant.ID,
			MembershipID: membership.ID,
			RoleID:       ownerRole.ID,
		},
	)
	if err != nil {
		return RegisterResult{}, fmt.Errorf(
			"assign owner role: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return RegisterResult{}, mapRegistrationError(
			"commit registration transaction",
			err,
		)
	}

	result := RegisterResult{
		TenantID:     tenant.ID,
		UserID:       user.ID,
		MembershipID: membership.ID,
		OwnerRoleID:  ownerRole.ID,
	}

	delivery := EmailVerificationDelivery{
		RecipientEmail: user.Email,
		Token:          verificationToken,
		ExpiresAt:      storedVerification.ExpiresAt.Time,
	}

	if err := service.emailVerificationSender.SendEmailVerification(
		ctx,
		delivery,
	); err != nil {
		return result, fmt.Errorf(
			"%w: %v",
			ErrEmailVerificationDelivery,
			err,
		)
	}

	return result, nil
}

func normalizeRegistration(
	input RegisterInput,
) (RegisterInput, error) {
	input.TenantName = strings.TrimSpace(input.TenantName)
	input.TenantSlug = strings.ToLower(
		strings.TrimSpace(input.TenantSlug),
	)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.DisplayName = strings.TrimSpace(input.DisplayName)

	if !validName(input.TenantName) {
		return RegisterInput{}, fmt.Errorf(
			"%w: invalid tenant name",
			ErrInvalidRegistration,
		)
	}

	if len(input.TenantSlug) > 63 ||
		!tenantSlugPattern.MatchString(input.TenantSlug) {
		return RegisterInput{}, fmt.Errorf(
			"%w: invalid tenant slug",
			ErrInvalidRegistration,
		)
	}

	if !validEmail(input.Email) {
		return RegisterInput{}, fmt.Errorf(
			"%w: invalid email",
			ErrInvalidRegistration,
		)
	}

	if !validName(input.DisplayName) {
		return RegisterInput{}, fmt.Errorf(
			"%w: invalid display name",
			ErrInvalidRegistration,
		)
	}

	if len(input.Password) < minPasswordLength ||
		len(input.Password) > maxPasswordLength {
		return RegisterInput{}, fmt.Errorf(
			"%w: password must contain between %d and %d bytes",
			ErrInvalidRegistration,
			minPasswordLength,
			maxPasswordLength,
		)
	}

	return input, nil
}

func validName(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}

	length := utf8.RuneCountInString(value)
	return length >= 1 && length <= maxNameLength
}

func validEmail(value string) bool {
	if value == "" || len(value) > maxEmailLength {
		return false
	}

	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value
}

func mapRegistrationError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.ConstraintName {
		case "users_email_unique":
			return ErrEmailAlreadyExists

		case "tenants_slug_unique":
			return ErrTenantSlugUnavailable
		}
	}

	return fmt.Errorf("%s: %w", operation, err)
}
