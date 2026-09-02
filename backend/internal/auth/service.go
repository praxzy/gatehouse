package auth

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

var ErrInvalidServiceConfiguration = errors.New(
	"invalid authentication service configuration",
)

type ServiceOption func(*Service) error

type Service struct {
	pool                       *pgxpool.Pool
	queries                    *store.Queries
	auditWriter                audit.EventWriter
	loginRateLimiter           LoginRateLimiter
	dummyPasswordHash          string
	mfaSecretCipher            MFASecretCipher
	emailVerificationSender    EmailVerificationSender
	membershipInvitationSender MembershipInvitationSender
}

func WithMFASecretCipher(
	secretCipher MFASecretCipher,
) ServiceOption {
	return func(service *Service) error {
		if secretCipher == nil {
			return ErrInvalidServiceConfiguration
		}

		service.mfaSecretCipher = secretCipher
		return nil
	}
}

func WithEmailVerificationSender(
	sender EmailVerificationSender,
) ServiceOption {
	return func(service *Service) error {
		if sender == nil {
			return ErrInvalidServiceConfiguration
		}

		service.emailVerificationSender = sender
		return nil
	}
}

func WithMembershipInvitationSender(
	sender MembershipInvitationSender,
) ServiceOption {
	return func(service *Service) error {
		if sender == nil {
			return ErrInvalidServiceConfiguration
		}

		service.membershipInvitationSender = sender
		return nil
	}
}

func NewService(
	pool *pgxpool.Pool,
	loginRateLimiter LoginRateLimiter,
	auditWriter audit.EventWriter,
	options ...ServiceOption,
) (*Service, error) {
	if pool == nil || loginRateLimiter == nil || auditWriter == nil {
		return nil, ErrInvalidServiceConfiguration
	}

	dummyPasswordHash, err := HashPassword(
		"gatehouse dummy authentication password",
	)
	if err != nil {
		return nil, fmt.Errorf("create dummy password hash: %w", err)
	}

	service := &Service{
		pool:              pool,
		queries:           store.New(pool),
		auditWriter:       auditWriter,
		loginRateLimiter:  loginRateLimiter,
		dummyPasswordHash: dummyPasswordHash,
	}

	for _, option := range options {
		if option == nil {
			return nil, ErrInvalidServiceConfiguration
		}

		if err := option(service); err != nil {
			return nil, err
		}
	}

	if service.mfaSecretCipher == nil ||
		service.emailVerificationSender == nil ||
		service.membershipInvitationSender == nil {
		return nil, ErrInvalidServiceConfiguration
	}

	return service, nil
}
