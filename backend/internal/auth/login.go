package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")

	ErrEmailVerificationRequired = errors.New(
		"email verification required",
	)

	ErrLoginRateLimited  = errors.New("login rate limit exceeded")
	ErrInvalidLoginInput = errors.New("invalid login input")
)

type LoginInput struct {
	Email    string
	Password string
	ClientIP string
}

type LoginResult struct {
	UserID pgtype.UUID
	Email  string
}

type LoginRateLimitedError struct {
	RetryAfter time.Duration
}

func (err *LoginRateLimitedError) Error() string {
	return fmt.Sprintf(
		"%s; retry after %s",
		ErrLoginRateLimited,
		err.RetryAfter,
	)
}

func (err *LoginRateLimitedError) Unwrap() error {
	return ErrLoginRateLimited
}

func (service *Service) Login(
	ctx context.Context,
	input LoginInput,
) (LoginResult, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))

	clientIP, err := netip.ParseAddr(strings.TrimSpace(input.ClientIP))
	if err != nil {
		return LoginResult{}, fmt.Errorf(
			"%w: invalid client IP",
			ErrInvalidLoginInput,
		)
	}

	clientIP = clientIP.Unmap()

	decision, err := service.loginRateLimiter.Allow(
		ctx,
		"ip:"+clientIP.String(),
		accountRateLimitKey(email),
	)
	if err != nil {
		return LoginResult{}, fmt.Errorf(
			"check login rate limit: %w",
			err,
		)
	}

	if !decision.Allowed {
		loginErr := &LoginRateLimitedError{
			RetryAfter: decision.RetryAfter,
		}

		return LoginResult{}, service.rejectLoginAttempt(
			ctx,
			audit.OutcomeDenied,
			"rate_limited",
			pgtype.UUID{},
			loginErr,
		)
	}

	if !validEmail(email) {
		return LoginResult{}, service.rejectUnknownCredentials(
			ctx,
			input.Password,
		)
	}

	login, err := service.queries.GetPasswordLoginByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginResult{}, service.rejectUnknownCredentials(
			ctx,
			input.Password,
		)
	}

	if err != nil {
		return LoginResult{}, fmt.Errorf(
			"load password credential: %w",
			err,
		)
	}

	matches, err := VerifyPassword(
		input.Password,
		login.PasswordHash,
	)
	if err != nil {
		return LoginResult{}, fmt.Errorf(
			"verify stored password: %w",
			err,
		)
	}

	if !matches {
		return LoginResult{}, service.rejectLoginAttempt(
			ctx,
			audit.OutcomeFailure,
			"invalid_credentials",
			login.UserID,
			ErrInvalidCredentials,
		)
	}

	if login.Status != "active" {
		return LoginResult{}, service.rejectLoginAttempt(
			ctx,
			audit.OutcomeDenied,
			"inactive_account",
			login.UserID,
			ErrInvalidCredentials,
		)
	}

	if !login.EmailVerified {
		return LoginResult{}, service.rejectLoginAttempt(
			ctx,
			audit.OutcomeDenied,
			"email_verification_required",
			login.UserID,
			ErrEmailVerificationRequired,
		)
	}

	return LoginResult{
		UserID: login.UserID,
		Email:  login.Email,
	}, nil
}

func (service *Service) rejectUnknownCredentials(
	ctx context.Context,
	password string,
) error {
	_, err := VerifyPassword(password, service.dummyPasswordHash)
	if err != nil {
		return fmt.Errorf("verify dummy password: %w", err)
	}

	return service.rejectLoginAttempt(
		ctx,
		audit.OutcomeFailure,
		"invalid_credentials",
		pgtype.UUID{},
		ErrInvalidCredentials,
	)
}

func accountRateLimitKey(email string) string {
	digest := sha256.Sum256([]byte(email))

	return "account:" + hex.EncodeToString(digest[:])
}

func (service *Service) rejectLoginAttempt(
	ctx context.Context,
	outcome audit.Outcome,
	failureReason string,
	subjectUserID pgtype.UUID,
	loginErr error,
) error {
	event := audit.Event{
		ActorKind: audit.ActorAnonymous,
		Type:      audit.EventLogin,
		Outcome:   outcome,
		Metadata: audit.Metadata{
			"authentication_method": "password",
			"failure_reason":        failureReason,
		},
	}

	if subjectUserID.Valid {
		event.SubjectType = "user"
		event.SubjectID = subjectUserID
	}

	_, err := service.auditWriter.Write(
		ctx,
		service.queries,
		event,
	)
	if err != nil {
		return fmt.Errorf("audit rejected login: %w", err)
	}

	return loginErr
}
