package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	sessionTokenBytes      = 32
	sessionLifetimeSeconds = 12 * 60 * 60
	maxRevocationReason    = 100
)

var (
	ErrInvalidSession          = errors.New("invalid or expired session")
	ErrInactiveMembership      = errors.New("active tenant membership not found")
	ErrInvalidRevocationReason = errors.New("invalid session revocation reason")
)

type AuthenticateInput struct {
	TenantSlug      string
	Email           string
	Password        string
	ClientIP        string
	PreviousSession string
}

type AuthenticateResult struct {
	UserID  pgtype.UUID
	Email   string
	Session SessionGrant
}

type SessionGrant struct {
	Token        string
	SessionID    pgtype.UUID
	TenantID     pgtype.UUID
	MembershipID pgtype.UUID
	UserID       pgtype.UUID
	ExpiresAt    time.Time
}

type SessionContext struct {
	SessionID           pgtype.UUID
	TenantID            pgtype.UUID
	MembershipID        pgtype.UUID
	UserID              pgtype.UUID
	AuthenticationLevel string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	Email               string
	DisplayName         string
	TenantName          string
	TenantSlug          string
	MFARequired         bool
	MFAEnrolled         bool
}

func (service *Service) AuthenticateAndCreateSession(
	ctx context.Context,
	input AuthenticateInput,
) (AuthenticateResult, error) {
	login, err := service.Login(
		ctx,
		LoginInput{
			Email:    input.Email,
			Password: input.Password,
			ClientIP: input.ClientIP,
		},
	)
	if err != nil {
		return AuthenticateResult{}, err
	}

	tenantSlug := strings.ToLower(strings.TrimSpace(input.TenantSlug))
	if !tenantSlugPattern.MatchString(tenantSlug) {
		return AuthenticateResult{}, ErrInvalidCredentials
	}

	session, err := service.CreateAuthenticatedSession(
		ctx,
		login.UserID,
		tenantSlug,
		input.PreviousSession,
	)
	if errors.Is(err, ErrInactiveMembership) {
		return AuthenticateResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return AuthenticateResult{}, err
	}

	return AuthenticateResult{
		UserID:  login.UserID,
		Email:   login.Email,
		Session: session,
	}, nil
}

func (service *Service) CreateAuthenticatedSession(
	ctx context.Context,
	userID pgtype.UUID,
	tenantSlug string,
	previousToken string,
) (SessionGrant, error) {
	rawToken, tokenHash, err := generateSessionToken()
	if err != nil {
		return SessionGrant{}, err
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"begin session transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	membership, err := queries.GetActiveMembershipForSessionCreation(
		ctx,
		store.GetActiveMembershipForSessionCreationParams{
			UserID:     userID,
			TenantSlug: tenantSlug,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionGrant{}, ErrInactiveMembership
	}
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"load membership for session: %w",
			err,
		)
	}

	if previousToken != "" {
		previousHash, hashErr := hashSessionToken(previousToken)
		if hashErr == nil {
			reason := "rotated_after_authentication"

			_, err = queries.RevokeSessionByTokenHash(
				ctx,
				store.RevokeSessionByTokenHashParams{
					RevocationReason: &reason,
					TokenHash:        previousHash,
				},
			)
			if err != nil {
				return SessionGrant{}, fmt.Errorf(
					"revoke previous session: %w",
					err,
				)
			}
		}
	}

	session, err := queries.CreateSession(
		ctx,
		store.CreateSessionParams{
			TenantID:            membership.TenantID,
			MembershipID:        membership.MembershipID,
			UserID:              membership.UserID,
			TokenHash:           tokenHash,
			AuthenticationLevel: "password",
			LifetimeSeconds:     sessionLifetimeSeconds,
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf("create session: %w", err)
	}

	if err := transaction.Commit(ctx); err != nil {
		return SessionGrant{}, fmt.Errorf(
			"commit session transaction: %w",
			err,
		)
	}

	if !session.ExpiresAt.Valid {
		return SessionGrant{}, errors.New(
			"created session has no expiration",
		)
	}

	return SessionGrant{
		Token:        rawToken,
		SessionID:    session.ID,
		TenantID:     session.TenantID,
		MembershipID: session.MembershipID,
		UserID:       session.UserID,
		ExpiresAt:    session.ExpiresAt.Time,
	}, nil
}

func (service *Service) ResolveSession(
	ctx context.Context,
	rawToken string,
) (SessionContext, error) {
	tokenHash, err := hashSessionToken(rawToken)
	if err != nil {
		return SessionContext{}, ErrInvalidSession
	}

	session, err := service.queries.GetActiveSessionByTokenHash(
		ctx,
		tokenHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionContext{}, ErrInvalidSession
	}
	if err != nil {
		return SessionContext{}, fmt.Errorf(
			"resolve session: %w",
			err,
		)
	}

	if !session.CreatedAt.Valid || !session.ExpiresAt.Valid {
		return SessionContext{}, errors.New(
			"stored session has invalid timestamps",
		)
	}

	return SessionContext{
		SessionID:           session.SessionID,
		TenantID:            session.TenantID,
		MembershipID:        session.MembershipID,
		UserID:              session.UserID,
		AuthenticationLevel: session.AuthenticationLevel,
		CreatedAt:           session.CreatedAt.Time,
		ExpiresAt:           session.ExpiresAt.Time,
		Email:               session.Email,
		DisplayName:         session.DisplayName,
		TenantName:          session.TenantName,
		TenantSlug:          session.TenantSlug,
		MFARequired:         session.MfaRequired,
		MFAEnrolled:         session.MfaEnrolled,
	}, nil
}

func (service *Service) RevokeSession(
	ctx context.Context,
	session SessionContext,
	reason string,
) error {
	reason = strings.TrimSpace(reason)

	if !utf8.ValidString(reason) ||
		utf8.RuneCountInString(reason) < 1 ||
		utf8.RuneCountInString(reason) > maxRevocationReason {
		return ErrInvalidRevocationReason
	}

	_, err := service.queries.RevokeSessionByID(
		ctx,
		store.RevokeSessionByIDParams{
			RevocationReason: &reason,
			TenantID:         session.TenantID,
			SessionID:        session.SessionID,
		},
	)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func generateSessionToken() (string, []byte, error) {
	tokenBytes := make([]byte, sessionTokenBytes)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}

	rawToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256(tokenBytes)

	return rawToken, digest[:], nil
}

func hashSessionToken(rawToken string) ([]byte, error) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(rawToken)
	if err != nil || len(tokenBytes) != sessionTokenBytes {
		return nil, ErrInvalidSession
	}

	digest := sha256.Sum256(tokenBytes)
	return digest[:], nil
}
