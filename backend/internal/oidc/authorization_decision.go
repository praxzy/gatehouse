package oidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type AuthorizationStep string

const (
	AuthorizationStepLoginRequired AuthorizationStep = "login_required"

	AuthorizationStepMFAEnrollmentRequired AuthorizationStep = "mfa_enrollment_required"

	AuthorizationStepMFAChallengeRequired AuthorizationStep = "mfa_challenge_required"

	AuthorizationStepGranted AuthorizationStep = "granted"

	AuthorizationStepDenied AuthorizationStep = "denied"
)

type AuthorizationSession struct {
	SessionID    pgtype.UUID
	TenantID     pgtype.UUID
	MembershipID pgtype.UUID
	UserID       pgtype.UUID
}

type AuthorizationDecision struct {
	Step              AuthorizationStep
	Authorization     PendingAuthorization
	Session           AuthorizationSession
	AuthorizationCode string
}

func (service *AuthorizationService) ContinueAuthorization(
	ctx context.Context,
	transactionID pgtype.UUID,
	state string,
	session *AuthorizationSession,
) (AuthorizationDecision, error) {
	authorization, err := service.LoadAuthorization(
		ctx,
		transactionID,
		state,
	)
	if err != nil {
		return AuthorizationDecision{}, err
	}

	if !validAuthorizationSession(
		session,
		authorization.TenantID,
	) {
		_, auditErr := service.auditWriter.Write(
			ctx,
			service.queries,
			audit.Event{
				TenantID:      authorization.TenantID,
				ActorKind:     audit.ActorAnonymous,
				ApplicationID: authorization.ApplicationID,
				Type:          audit.EventAuthorizationDecision,
				Outcome:       audit.OutcomeDenied,
				SubjectType:   "application",
				SubjectID:     authorization.ApplicationID,
				Metadata: audit.Metadata{
					"authentication_level": "none",
					"decision_reason":      "login_required",
				},
			},
		)
		if auditErr != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"audit login-required authorization decision: %w",
				auditErr,
			)
		}

		return AuthorizationDecision{
			Step:          AuthorizationStepLoginRequired,
			Authorization: authorization,
		}, nil
	}

	databaseTransaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return AuthorizationDecision{}, fmt.Errorf(
			"begin authorization decision transaction: %w",
			err,
		)
	}

	defer func() {
		_ = databaseTransaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(databaseTransaction)

	evaluation, err :=
		queries.EvaluateAuthorizationSession(
			ctx,
			store.EvaluateAuthorizationSessionParams{
				ApplicationID: authorization.ApplicationID,
				SessionID:     session.SessionID,
				TenantID:      authorization.TenantID,
				MembershipID:  session.MembershipID,
				UserID:        session.UserID,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		_, auditErr := service.auditWriter.Write(
			ctx,
			queries,
			audit.Event{
				TenantID:      authorization.TenantID,
				ActorKind:     audit.ActorAnonymous,
				ApplicationID: authorization.ApplicationID,
				Type:          audit.EventAuthorizationDecision,
				Outcome:       audit.OutcomeDenied,
				SubjectType:   "application",
				SubjectID:     authorization.ApplicationID,
				Metadata: audit.Metadata{
					"authentication_level": "none",
					"decision_reason":      "login_required",
				},
			},
		)
		if auditErr != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"audit invalid-session authorization decision: %w",
				auditErr,
			)
		}

		if err := databaseTransaction.Commit(ctx); err != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"commit invalid-session authorization decision: %w",
				err,
			)
		}

		return AuthorizationDecision{
			Step:          AuthorizationStepLoginRequired,
			Authorization: authorization,
		}, nil
	}
	if err != nil {
		return AuthorizationDecision{},
			fmt.Errorf(
				"evaluate authorization session: %w",
				err,
			)
	}

	decision := AuthorizationDecision{
		Authorization: authorization,
		Session:       *session,
	}

	if evaluation.MfaRequired &&
		evaluation.AuthenticationLevel != "mfa" {
		decisionReason := "mfa_enrollment_required"

		if evaluation.MfaEnrolled {
			decision.Step =
				AuthorizationStepMFAChallengeRequired
			decisionReason = "mfa_challenge_required"
		} else {
			decision.Step =
				AuthorizationStepMFAEnrollmentRequired
		}

		_, err = service.auditWriter.Write(
			ctx,
			queries,
			audit.Event{
				TenantID:          authorization.TenantID,
				ActorKind:         audit.ActorUser,
				ActorUserID:       session.UserID,
				ActorMembershipID: session.MembershipID,
				ApplicationID:     authorization.ApplicationID,
				SessionID:         session.SessionID,
				Type:              audit.EventAuthorizationDecision,
				Outcome:           audit.OutcomeDenied,
				SubjectType:       "application",
				SubjectID:         authorization.ApplicationID,
				Metadata: audit.Metadata{
					"authentication_level": evaluation.AuthenticationLevel,
					"decision_reason":      decisionReason,
				},
			},
		)
		if err != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"audit MFA-required authorization decision: %w",
				err,
			)
		}

		if err := databaseTransaction.Commit(ctx); err != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"commit MFA-required authorization decision: %w",
				err,
			)
		}

		return decision, nil
	}

	stateHash := sha256.Sum256([]byte(state))

	if !evaluation.AccessGranted {
		affected, err :=
			queries.ConsumeDeniedAuthorizationTransaction(
				ctx,
				store.ConsumeDeniedAuthorizationTransactionParams{
					TransactionID: authorization.TransactionID,
					TenantID:      authorization.TenantID,
					ApplicationID: authorization.ApplicationID,
					StateHash:     stateHash[:],
				},
			)
		if err != nil {
			return AuthorizationDecision{},
				fmt.Errorf(
					"consume denied authorization transaction: %w",
					err,
				)
		}

		if affected != 1 {
			return AuthorizationDecision{},
				ErrAuthorizationTransactionConsumed
		}

		_, err = service.auditWriter.Write(
			ctx,
			queries,
			audit.Event{
				TenantID:          authorization.TenantID,
				ActorKind:         audit.ActorUser,
				ActorUserID:       session.UserID,
				ActorMembershipID: session.MembershipID,
				ApplicationID:     authorization.ApplicationID,
				SessionID:         session.SessionID,
				Type:              audit.EventAuthorizationDecision,
				Outcome:           audit.OutcomeDenied,
				SubjectType:       "application",
				SubjectID:         authorization.ApplicationID,
				Metadata: audit.Metadata{
					"authentication_level": evaluation.AuthenticationLevel,
					"decision_reason":      "application_access_denied",
				},
			},
		)
		if err != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"audit denied authorization decision: %w",
				err,
			)
		}

		if err := databaseTransaction.Commit(ctx); err != nil {
			return AuthorizationDecision{}, fmt.Errorf(
				"commit denied authorization decision: %w",
				err,
			)
		}

		decision.Step = AuthorizationStepDenied
		return decision, nil
	}

	rawCode, codeHash, err :=
		generateAuthorizationCode()
	if err != nil {
		return AuthorizationDecision{}, err
	}

	_, err = queries.IssueAuthorizationCode(
		ctx,
		store.IssueAuthorizationCodeParams{
			CodeHash: codeHash,
			CodeExpiresAt: pgtype.Timestamptz{
				Time: service.now().
					UTC().
					Add(authorizationCodeLifetime),
				Valid: true,
			},
			SessionID:     session.SessionID,
			MembershipID:  session.MembershipID,
			UserID:        session.UserID,
			TransactionID: authorization.TransactionID,
			TenantID:      authorization.TenantID,
			ApplicationID: authorization.ApplicationID,
			StateHash:     stateHash[:],
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthorizationDecision{},
			ErrAuthorizationGrantUnavailable
	}
	if err != nil {
		return AuthorizationDecision{},
			fmt.Errorf(
				"issue authorization code: %w",
				err,
			)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          authorization.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			ApplicationID:     authorization.ApplicationID,
			SessionID:         session.SessionID,
			Type:              audit.EventAuthorizationDecision,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "application",
			SubjectID:         authorization.ApplicationID,
			Metadata: audit.Metadata{
				"authentication_level": evaluation.AuthenticationLevel,
				"decision_reason":      "application_access_granted",
			},
		},
	)
	if err != nil {
		return AuthorizationDecision{}, fmt.Errorf(
			"audit granted authorization decision: %w",
			err,
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          authorization.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			ApplicationID:     authorization.ApplicationID,
			SessionID:         session.SessionID,
			Type:              audit.EventAuthorizationCodeIssued,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "authorization_transaction",
			SubjectID:         authorization.TransactionID,
			Metadata: audit.Metadata{
				"expires_in_seconds": int(
					authorizationCodeLifetime / time.Second,
				),
			},
		},
	)
	if err != nil {
		return AuthorizationDecision{}, fmt.Errorf(
			"audit authorization code issuance: %w",
			err,
		)
	}

	if err := databaseTransaction.Commit(ctx); err != nil {
		return AuthorizationDecision{}, fmt.Errorf(
			"commit granted authorization decision: %w",
			err,
		)
	}

	decision.Step = AuthorizationStepGranted
	decision.AuthorizationCode = rawCode

	return decision, nil
}

func validAuthorizationSession(
	session *AuthorizationSession,
	expectedTenantID pgtype.UUID,
) bool {
	return session != nil &&
		session.SessionID.Valid &&
		session.TenantID.Valid &&
		session.MembershipID.Valid &&
		session.UserID.Valid &&
		session.TenantID == expectedTenantID
}
