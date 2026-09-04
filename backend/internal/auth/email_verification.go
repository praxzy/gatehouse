package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

const (
	emailVerificationTokenBytes      = 32
	emailVerificationLifetimeSeconds = 24 * 60 * 60
)

var (
	ErrInvalidEmailVerificationToken = errors.New(
		"invalid or expired email verification token",
	)

	ErrEmailVerificationDelivery = errors.New(
		"email verification delivery failed",
	)
)

type EmailVerificationDelivery struct {
	RecipientEmail string
	Token          string
	ExpiresAt      time.Time
}

type VerifyEmailResult struct {
	UserID     pgtype.UUID
	Email      string
	VerifiedAt time.Time
}

type EmailVerificationSender interface {
	SendEmailVerification(
		ctx context.Context,
		delivery EmailVerificationDelivery,
	) error
}

func generateEmailVerificationToken() (
	rawToken string,
	tokenHash []byte,
	err error,
) {
	tokenBytes := make([]byte, emailVerificationTokenBytes)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, err
	}

	rawToken = base64.RawURLEncoding.EncodeToString(tokenBytes)
	digest := sha256.Sum256(tokenBytes)

	return rawToken, digest[:], nil
}

func hashEmailVerificationToken(
	rawToken string,
) ([]byte, error) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(rawToken)
	if err != nil || len(tokenBytes) != emailVerificationTokenBytes {
		return nil, ErrInvalidEmailVerificationToken
	}

	digest := sha256.Sum256(tokenBytes)
	return digest[:], nil
}

func (service *Service) VerifyEmail(
	ctx context.Context,
	rawToken string,
) (VerifyEmailResult, error) {
	tokenHash, err := hashEmailVerificationToken(rawToken)
	if err != nil {
		return VerifyEmailResult{},
			ErrInvalidEmailVerificationToken
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return VerifyEmailResult{}, fmt.Errorf(
			"begin email verification transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	verifiedUser, err :=
		queries.VerifyEmailByTokenHash(
			ctx,
			tokenHash,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return VerifyEmailResult{},
			ErrInvalidEmailVerificationToken
	}
	if err != nil {
		return VerifyEmailResult{}, fmt.Errorf(
			"verify email token: %w",
			err,
		)
	}

	if !verifiedUser.EmailVerifiedAt.Valid {
		return VerifyEmailResult{}, errors.New(
			"verified email has no verification timestamp",
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			ActorKind:   audit.ActorAnonymous,
			Type:        audit.EventEmailVerification,
			Outcome:     audit.OutcomeSuccess,
			SubjectType: "user",
			SubjectID:   verifiedUser.ID,
			Metadata: audit.Metadata{
				"verification_method": "email_link",
			},
		},
	)
	if err != nil {
		return VerifyEmailResult{}, fmt.Errorf(
			"audit email verification: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return VerifyEmailResult{}, fmt.Errorf(
			"commit email verification: %w",
			err,
		)
	}

	return VerifyEmailResult{
		UserID:     verifiedUser.ID,
		Email:      verifiedUser.Email,
		VerifiedAt: verifiedUser.EmailVerifiedAt.Time,
	}, nil
}
