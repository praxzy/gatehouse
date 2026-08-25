package oidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

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
		return AuthorizationDecision{
			Step:          AuthorizationStepLoginRequired,
			Authorization: authorization,
		}, nil
	}

	evaluation, err :=
		service.queries.EvaluateAuthorizationSession(
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
		if evaluation.MfaEnrolled {
			decision.Step =
				AuthorizationStepMFAChallengeRequired
		} else {
			decision.Step =
				AuthorizationStepMFAEnrollmentRequired
		}

		return decision, nil
	}

	stateHash := sha256.Sum256([]byte(state))

	if !evaluation.AccessGranted {
		affected, err :=
			service.queries.ConsumeDeniedAuthorizationTransaction(
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

		decision.Step = AuthorizationStepDenied
		return decision, nil
	}

	rawCode, codeHash, err :=
		generateAuthorizationCode()
	if err != nil {
		return AuthorizationDecision{}, err
	}

	_, err = service.queries.IssueAuthorizationCode(
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
