package auth

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const maxUpstreamSubjectBytes = 512

type CreateUpstreamSessionInput struct {
	TenantID        pgtype.UUID
	ConnectionID    pgtype.UUID
	Subject         string
	PreviousSession string
}

func (service *Service) CreateUpstreamSession(
	ctx context.Context,
	input CreateUpstreamSessionInput,
) (SessionGrant, error) {
	if !input.TenantID.Valid ||
		!input.ConnectionID.Valid ||
		input.Subject == "" ||
		len(input.Subject) > maxUpstreamSubjectBytes ||
		!utf8.ValidString(input.Subject) {
		return SessionGrant{}, ErrInactiveMembership
	}

	rawToken, tokenHash, err := generateSessionToken()
	if err != nil {
		return SessionGrant{}, err
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"begin upstream session transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	identity, err :=
		queries.GetActiveUpstreamOIDCIdentityForSessionCreation(
			ctx,
			store.GetActiveUpstreamOIDCIdentityForSessionCreationParams{
				TenantID:     input.TenantID,
				ConnectionID: input.ConnectionID,
				Subject:      input.Subject,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionGrant{}, ErrInactiveMembership
	}
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"load upstream identity mapping: %w",
			err,
		)
	}

	if identity.TenantID != input.TenantID ||
		identity.ConnectionID != input.ConnectionID ||
		identity.Subject != input.Subject ||
		!identity.MembershipID.Valid ||
		!identity.UserID.Valid {
		return SessionGrant{}, ErrInactiveMembership
	}

	rotatedPreviousSession := false

	if input.PreviousSession != "" {
		previousHash, hashErr :=
			hashSessionToken(input.PreviousSession)

		if hashErr == nil {
			reason := "rotated_after_upstream_authentication"

			revokedSessions, revokeErr :=
				queries.RevokeSessionByTokenHash(
					ctx,
					store.RevokeSessionByTokenHashParams{
						RevocationReason: &reason,
						TokenHash:        previousHash,
					},
				)
			if revokeErr != nil {
				return SessionGrant{}, fmt.Errorf(
					"revoke previous session: %w",
					revokeErr,
				)
			}

			rotatedPreviousSession =
				revokedSessions > 0
		}
	}

	session, err := queries.CreateSession(
		ctx,
		store.CreateSessionParams{
			TenantID:            identity.TenantID,
			MembershipID:        identity.MembershipID,
			UserID:              identity.UserID,
			TokenHash:           tokenHash,
			AuthenticationLevel: "upstream",
			LifetimeSeconds:     sessionLifetimeSeconds,
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"create upstream session: %w",
			err,
		)
	}

	if !session.ExpiresAt.Valid {
		return SessionGrant{}, errors.New(
			"created upstream session has no expiration",
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.ID,
			Type:              audit.EventLogin,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "session",
			SubjectID:         session.ID,
			Metadata: audit.Metadata{
				"authentication_method": "upstream_oidc",
			},
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"audit upstream login: %w",
			err,
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.ID,
			Type:              audit.EventSessionCreated,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "session",
			SubjectID:         session.ID,
			Metadata: audit.Metadata{
				"authentication_level":     "upstream",
				"rotated_previous_session": rotatedPreviousSession,
			},
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"audit upstream session creation: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return SessionGrant{}, fmt.Errorf(
			"commit upstream session transaction: %w",
			err,
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
