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
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrLoginRateLimited   = errors.New("login rate limit exceeded")
	ErrInvalidLoginInput  = errors.New("invalid login input")
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
		return LoginResult{}, &LoginRateLimitedError{
			RetryAfter: decision.RetryAfter,
		}
	}

	if !validEmail(email) {
		return LoginResult{}, service.rejectUnknownCredentials(
			input.Password,
		)
	}

	login, err := service.queries.GetPasswordLoginByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginResult{}, service.rejectUnknownCredentials(
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

	if !matches || login.Status != "active" {
		return LoginResult{}, ErrInvalidCredentials
	}

	return LoginResult{
		UserID: login.UserID,
		Email:  login.Email,
	}, nil
}

func (service *Service) rejectUnknownCredentials(
	password string,
) error {
	_, err := VerifyPassword(password, service.dummyPasswordHash)
	if err != nil {
		return fmt.Errorf("verify dummy password: %w", err)
	}

	return ErrInvalidCredentials
}

func accountRateLimitKey(email string) string {
	digest := sha256.Sum256([]byte(email))

	return "account:" + hex.EncodeToString(digest[:])
}
