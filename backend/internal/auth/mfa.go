package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	totpIssuer               = "Gatehouse"
	totpEnrollmentLifetime   = 10 * time.Minute
	defaultRecoveryCodeCount = 10
)

var (
	ErrMFAUnavailable = errors.New(
		"MFA service is unavailable",
	)
	ErrMFAAlreadyEnrolled = errors.New(
		"MFA is already enrolled",
	)
	ErrMFAEnrollmentNotFound = errors.New(
		"pending MFA enrollment not found",
	)
	ErrInvalidMFAChallenge = errors.New(
		"invalid MFA challenge",
	)
	ErrMFAAlreadySatisfied = errors.New(
		"MFA is already satisfied",
	)
	ErrMFAEnrollmentExpired = errors.New(
		"MFA enrollment expired",
	)
)

type TOTPEnrollmentResult struct {
	ProvisioningURI string
	ManualKey       string
	ExpiresAt       time.Time
}

type MFAEnrollmentConfirmation struct {
	Session       SessionGrant
	RecoveryCodes []string
}

type MFAChallengeResult struct {
	Session SessionGrant
}

func (service *Service) BeginTOTPEnrollment(
	ctx context.Context,
	session SessionContext,
) (TOTPEnrollmentResult, error) {
	if err := service.requireMFACipher(); err != nil {
		return TOTPEnrollmentResult{}, err
	}

	secret, err := GenerateTOTPSecret()
	if err != nil {
		return TOTPEnrollmentResult{}, err
	}

	encrypted, err := service.mfaSecretCipher.Encrypt(
		session.UserID,
		secret,
	)
	if err != nil {
		return TOTPEnrollmentResult{}, err
	}

	provisioningURI, err := TOTPProvisioningURI(
		totpIssuer,
		session.Email,
		secret,
	)
	if err != nil {
		return TOTPEnrollmentResult{}, err
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return TOTPEnrollmentResult{}, fmt.Errorf(
			"begin MFA enrollment transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	credential, err := queries.UpsertPendingTOTPCredential(
		ctx,
		store.UpsertPendingTOTPCredentialParams{
			UserID:           session.UserID,
			SecretCiphertext: encrypted.Ciphertext,
			SecretNonce:      encrypted.Nonce,
			EncryptionKeyID:  encrypted.KeyID,
			LifetimeSeconds:  int32(totpEnrollmentLifetime / time.Second),
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return TOTPEnrollmentResult{}, ErrMFAAlreadyEnrolled
	}
	if err != nil {
		return TOTPEnrollmentResult{}, fmt.Errorf(
			"store pending TOTP credential: %w",
			err,
		)
	}
	if !credential.EnrollmentExpiresAt.Valid {
		return TOTPEnrollmentResult{}, errors.New(
			"pending MFA enrollment has no expiry",
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
			SessionID:         session.SessionID,
			Type:              audit.EventMFAEnrollmentStarted,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "user",
			SubjectID:         session.UserID,
			Metadata: audit.Metadata{
				"expires_in_seconds": int(totpEnrollmentLifetime / time.Second),
			},
		},
	)
	if err != nil {
		return TOTPEnrollmentResult{}, fmt.Errorf(
			"audit MFA enrollment start: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return TOTPEnrollmentResult{}, fmt.Errorf(
			"commit MFA enrollment start: %w",
			err,
		)
	}

	return TOTPEnrollmentResult{
		ProvisioningURI: provisioningURI,
		ManualKey:       totpBase32.EncodeToString(secret),
		ExpiresAt:       credential.EnrollmentExpiresAt.Time,
	}, nil
}

func (service *Service) ConfirmTOTPEnrollment(
	ctx context.Context,
	session SessionContext,
	code string,
) (MFAEnrollmentConfirmation, error) {
	result, err := service.confirmTOTPEnrollment(
		ctx,
		session,
		code,
	)
	if err == nil {
		return result, nil
	}

	var failureReason string

	switch {
	case errors.Is(err, ErrInvalidMFAChallenge):
		failureReason = "invalid_code"

	case errors.Is(err, ErrMFAEnrollmentExpired):
		failureReason = "enrollment_expired"

	case errors.Is(err, ErrMFAEnrollmentNotFound):
		failureReason = "enrollment_not_found"

	case errors.Is(err, ErrMFAAlreadyEnrolled):
		failureReason = "already_enrolled"

	default:
		return result, err
	}

	_, auditErr := service.auditWriter.Write(
		ctx,
		service.queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type:              audit.EventMFAEnrollmentConfirmed,
			Outcome:           audit.OutcomeFailure,
			SubjectType:       "user",
			SubjectID:         session.UserID,
			Metadata: audit.Metadata{
				"failure_reason": failureReason,
			},
		},
	)
	if auditErr != nil {
		return MFAEnrollmentConfirmation{}, fmt.Errorf(
			"audit rejected MFA enrollment confirmation: %w",
			auditErr,
		)
	}

	return result, err
}

func (service *Service) confirmTOTPEnrollment(
	ctx context.Context,
	session SessionContext,
	code string,
) (MFAEnrollmentConfirmation, error) {
	if err := service.requireMFACipher(); err != nil {
		return MFAEnrollmentConfirmation{}, err
	}

	recoveryCodes, err := GenerateRecoveryCodes(
		defaultRecoveryCodeCount,
	)
	if err != nil {
		return MFAEnrollmentConfirmation{}, err
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return MFAEnrollmentConfirmation{}, fmt.Errorf(
			"begin MFA confirmation transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	credential, err := queries.GetTOTPCredentialForUpdate(
		ctx,
		session.UserID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAEnrollmentConfirmation{},
			ErrMFAEnrollmentNotFound
	}
	if err != nil {
		return MFAEnrollmentConfirmation{}, fmt.Errorf(
			"load pending TOTP credential: %w",
			err,
		)
	}

	if credential.Status != "pending" {
		return MFAEnrollmentConfirmation{}, ErrMFAAlreadyEnrolled
	}

	if !credential.EnrollmentExpiresAt.Valid ||
		!credential.EnrollmentExpiresAt.Time.After(time.Now()) {
		return MFAEnrollmentConfirmation{},
			ErrMFAEnrollmentExpired
	}

	secret, err := service.decryptTOTPCredential(credential)
	if err != nil {
		return MFAEnrollmentConfirmation{}, err
	}

	acceptedStep, matches := MatchTOTPCode(
		secret,
		code,
		time.Now(),
	)
	if !matches {
		return MFAEnrollmentConfirmation{}, ErrInvalidMFAChallenge
	}

	affected, err := queries.ActivateTOTPCredential(
		ctx,
		store.ActivateTOTPCredentialParams{
			AcceptedTimestep: acceptedStep,
			UserID:           session.UserID,
		},
	)
	if err != nil {
		return MFAEnrollmentConfirmation{}, fmt.Errorf(
			"activate TOTP credential: %w",
			err,
		)
	}
	if affected != 1 {
		return MFAEnrollmentConfirmation{},
			ErrMFAEnrollmentExpired
	}

	for _, recoveryCode := range recoveryCodes {
		err := queries.CreateMFARecoveryCode(
			ctx,
			store.CreateMFARecoveryCodeParams{
				UserID:   session.UserID,
				CodeHash: recoveryCode.Hash,
			},
		)
		if err != nil {
			return MFAEnrollmentConfirmation{}, fmt.Errorf(
				"store recovery code: %w",
				err,
			)
		}
	}

	elevatedSession, err := service.createMFASession(
		ctx,
		queries,
		session,
	)
	if err != nil {
		return MFAEnrollmentConfirmation{}, err
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type:              audit.EventMFAEnrollmentConfirmed,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "user",
			SubjectID:         session.UserID,
			Metadata: audit.Metadata{
				"recovery_code_count": len(recoveryCodes),
			},
		},
	)
	if err != nil {
		return MFAEnrollmentConfirmation{}, fmt.Errorf(
			"audit MFA enrollment confirmation: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return MFAEnrollmentConfirmation{}, fmt.Errorf(
			"commit MFA confirmation: %w",
			err,
		)
	}

	rawCodes := make([]string, 0, len(recoveryCodes))
	for _, recoveryCode := range recoveryCodes {
		rawCodes = append(rawCodes, recoveryCode.Code)
	}

	return MFAEnrollmentConfirmation{
		Session:       elevatedSession,
		RecoveryCodes: rawCodes,
	}, nil
}

func (service *Service) CompleteMFAWithTOTP(
	ctx context.Context,
	session SessionContext,
	code string,
) (MFAChallengeResult, error) {
	result, err := service.completeMFAWithTOTP(
		ctx,
		session,
		code,
	)
	if !errors.Is(err, ErrInvalidMFAChallenge) {
		return result, err
	}

	_, auditErr := service.auditWriter.Write(
		ctx,
		service.queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type:              audit.EventMFAChallenge,
			Outcome:           audit.OutcomeFailure,
			SubjectType:       "user",
			SubjectID:         session.UserID,
			Metadata: audit.Metadata{
				"challenge_method": "totp",
				"failure_reason":   "invalid_or_replayed_code",
			},
		},
	)
	if auditErr != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"audit rejected TOTP challenge: %w",
			auditErr,
		)
	}

	return result, err
}

func (service *Service) completeMFAWithTOTP(
	ctx context.Context,
	session SessionContext,
	code string,
) (MFAChallengeResult, error) {
	if err := service.requireMFACipher(); err != nil {
		return MFAChallengeResult{}, err
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"begin TOTP challenge transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	credential, err := queries.GetTOTPCredentialForUpdate(
		ctx,
		session.UserID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"load TOTP credential: %w",
			err,
		)
	}

	if credential.Status != "active" {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}

	secret, err := service.decryptTOTPCredential(credential)
	if err != nil {
		return MFAChallengeResult{}, err
	}

	acceptedStep, matches := MatchTOTPCode(
		secret,
		code,
		time.Now(),
	)
	if !matches {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}

	affected, err := queries.ConsumeTOTPTimeStep(
		ctx,
		store.ConsumeTOTPTimeStepParams{
			AcceptedTimestep: acceptedStep,
			UserID:           session.UserID,
		},
	)
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"consume TOTP timestep: %w",
			err,
		)
	}
	if affected != 1 {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}

	elevatedSession, err := service.createMFASession(
		ctx,
		queries,
		session,
	)
	if err != nil {
		return MFAChallengeResult{}, err
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type:              audit.EventMFAChallenge,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "user",
			SubjectID:         session.UserID,
			Metadata: audit.Metadata{
				"challenge_method": "totp",
			},
		},
	)
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"audit TOTP challenge: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"commit TOTP challenge: %w",
			err,
		)
	}

	return MFAChallengeResult{
		Session: elevatedSession,
	}, nil
}

func (service *Service) CompleteMFAWithRecoveryCode(
	ctx context.Context,
	session SessionContext,
	code string,
) (MFAChallengeResult, error) {
	result, err := service.completeMFAWithRecoveryCode(
		ctx,
		session,
		code,
	)
	if !errors.Is(err, ErrInvalidMFAChallenge) {
		return result, err
	}

	_, auditErr := service.auditWriter.Write(
		ctx,
		service.queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type:              audit.EventMFARecoveryCode,
			Outcome:           audit.OutcomeFailure,
			SubjectType:       "user",
			SubjectID:         session.UserID,
			Metadata: audit.Metadata{
				"failure_reason": "invalid_or_reused_code",
			},
		},
	)
	if auditErr != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"audit rejected recovery-code challenge: %w",
			auditErr,
		)
	}

	return result, err
}

func (service *Service) completeMFAWithRecoveryCode(
	ctx context.Context,
	session SessionContext,
	code string,
) (MFAChallengeResult, error) {
	if err := service.requireMFACipher(); err != nil {
		return MFAChallengeResult{}, err
	}

	codeHash, err := HashRecoveryCode(code)
	if err != nil {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"begin recovery challenge transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	credential, err := queries.GetTOTPCredentialForUpdate(
		ctx,
		session.UserID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"load TOTP credential: %w",
			err,
		)
	}

	if credential.Status != "active" {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}

	affected, err := queries.ConsumeMFARecoveryCode(
		ctx,
		store.ConsumeMFARecoveryCodeParams{
			UserID:   session.UserID,
			CodeHash: codeHash,
		},
	)
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"consume recovery code: %w",
			err,
		)
	}
	if affected != 1 {
		return MFAChallengeResult{}, ErrInvalidMFAChallenge
	}

	elevatedSession, err := service.createMFASession(
		ctx,
		queries,
		session,
	)
	if err != nil {
		return MFAChallengeResult{}, err
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type:              audit.EventMFARecoveryCode,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "user",
			SubjectID:         session.UserID,
		},
	)
	if err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"audit recovery-code challenge: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return MFAChallengeResult{}, fmt.Errorf(
			"commit recovery challenge: %w",
			err,
		)
	}

	return MFAChallengeResult{
		Session: elevatedSession,
	}, nil
}

func (service *Service) createMFASession(
	ctx context.Context,
	queries *store.Queries,
	currentSession SessionContext,
) (SessionGrant, error) {
	if currentSession.AuthenticationLevel != "password" {
		return SessionGrant{}, ErrMFAAlreadySatisfied
	}

	membership, err := queries.GetActiveMembershipForSessionCreation(
		ctx,
		store.GetActiveMembershipForSessionCreationParams{
			UserID:     currentSession.UserID,
			TenantSlug: currentSession.TenantSlug,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SessionGrant{}, ErrInvalidSession
	}
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"reload membership for MFA session: %w",
			err,
		)
	}

	if membership.TenantID != currentSession.TenantID ||
		membership.MembershipID != currentSession.MembershipID ||
		membership.UserID != currentSession.UserID {
		return SessionGrant{}, ErrInvalidSession
	}

	revoked, err := queries.RevokePasswordSessionForMFA(
		ctx,
		store.RevokePasswordSessionForMFAParams{
			TenantID:     currentSession.TenantID,
			SessionID:    currentSession.SessionID,
			MembershipID: currentSession.MembershipID,
			UserID:       currentSession.UserID,
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"revoke password session for MFA: %w",
			err,
		)
	}
	if revoked != 1 {
		return SessionGrant{}, ErrInvalidSession
	}

	rawToken, tokenHash, err := generateSessionToken()
	if err != nil {
		return SessionGrant{}, err
	}

	session, err := queries.CreateSession(
		ctx,
		store.CreateSessionParams{
			TenantID:            currentSession.TenantID,
			MembershipID:        currentSession.MembershipID,
			UserID:              currentSession.UserID,
			TokenHash:           tokenHash,
			AuthenticationLevel: "mfa",
			LifetimeSeconds:     sessionLifetimeSeconds,
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"create MFA session: %w",
			err,
		)
	}

	if !session.ExpiresAt.Valid {
		return SessionGrant{}, errors.New(
			"created MFA session has no expiration",
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          currentSession.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       currentSession.UserID,
			ActorMembershipID: currentSession.MembershipID,
			SessionID:         currentSession.SessionID,
			Type:              audit.EventSessionRevoked,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "session",
			SubjectID:         currentSession.SessionID,
			Metadata: audit.Metadata{
				"revocation_reason": "rotated_after_mfa",
			},
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"audit MFA session revocation: %w",
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
				"authentication_level":     "mfa",
				"rotated_previous_session": true,
			},
		},
	)
	if err != nil {
		return SessionGrant{}, fmt.Errorf(
			"audit MFA session creation: %w",
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

func (service *Service) decryptTOTPCredential(
	credential store.TotpCredential,
) ([]byte, error) {
	secret, err := service.mfaSecretCipher.Decrypt(
		credential.UserID,
		EncryptedMFASecret{
			Ciphertext: credential.SecretCiphertext,
			Nonce:      credential.SecretNonce,
			KeyID:      credential.EncryptionKeyID,
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decrypt TOTP credential: %w",
			err,
		)
	}

	return secret, nil
}

func (service *Service) requireMFACipher() error {
	if service.mfaSecretCipher == nil {
		return ErrMFAUnavailable
	}

	return nil
}
