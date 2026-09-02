package oidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

const authorizationTransactionLifetime = 5 * time.Minute

var (
	ErrInvalidAuthorizationServiceConfiguration = errors.New(
		"invalid authorization service configuration",
	)
	ErrAuthorizationClientUnavailable = errors.New(
		"authorization client unavailable",
	)
	ErrAuthorizationTransactionNotFound = errors.New(
		"authorization transaction not found",
	)
	ErrAuthorizationTransactionExpired = errors.New(
		"authorization transaction expired",
	)
	ErrAuthorizationTransactionConsumed = errors.New(
		"authorization transaction already consumed",
	)
	ErrAuthorizationGrantUnavailable = errors.New(
		"authorization grant unavailable",
	)
)

type AuthorizationService struct {
	queries     *store.Queries
	auditWriter audit.EventWriter
	now         func() time.Time
}

type PendingAuthorization struct {
	TransactionID   pgtype.UUID
	TenantID        pgtype.UUID
	ApplicationID   pgtype.UUID
	ApplicationName string
	ClientID        string
	RedirectURI     string
	AccessMode      string
	RequestedScope  []string
	Nonce           string
	CodeChallenge   string
	ExpiresAt       time.Time
	TenantSlug      string
}

type AuthorizationProtocolError struct {
	Code        string
	RedirectURI string
	State       string
	cause       error
}

func (protocolError *AuthorizationProtocolError) Error() string {
	return protocolError.Code
}

func (protocolError *AuthorizationProtocolError) Unwrap() error {
	return protocolError.cause
}

func NewAuthorizationService(
	pool *pgxpool.Pool,
	auditWriter audit.EventWriter,
) (*AuthorizationService, error) {
	if pool == nil || auditWriter == nil {
		return nil, ErrInvalidAuthorizationServiceConfiguration
	}

	return &AuthorizationService{
		queries:     store.New(pool),
		auditWriter: auditWriter,
		now:         time.Now,
	}, nil
}

func (service *AuthorizationService) BeginAuthorization(
	ctx context.Context,
	values url.Values,
) (PendingAuthorization, error) {
	if service == nil ||
		service.queries == nil ||
		service.now == nil ||
		service.auditWriter == nil {
		return PendingAuthorization{},
			ErrInvalidAuthorizationServiceConfiguration
	}

	target, err := ParseAuthorizationTarget(values)
	if err != nil {
		return PendingAuthorization{},
			ErrAuthorizationClientUnavailable
	}

	application, err :=
		service.queries.GetActiveApplicationForAuthorization(
			ctx,
			store.GetActiveApplicationForAuthorizationParams{
				ClientID:    target.ClientID,
				RedirectUri: target.RedirectURI,
			},
		)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PendingAuthorization{},
				ErrAuthorizationClientUnavailable
		}

		return PendingAuthorization{},
			fmt.Errorf("load authorization client: %w", err)
	}

	request, err := ParseAuthorizationRequest(values)
	if err != nil {
		return PendingAuthorization{},
			newAuthorizationProtocolError(
				err,
				target.RedirectURI,
				values,
			)
	}

	now := service.now().UTC()
	stateHash := sha256.Sum256([]byte(request.State))

	transaction, err :=
		service.queries.CreateAuthorizationTransaction(
			ctx,
			store.CreateAuthorizationTransactionParams{
				TenantID:       application.TenantID,
				ApplicationID:  application.ApplicationID,
				ClientID:       application.ClientID,
				RedirectUri:    request.RedirectURI,
				StateHash:      stateHash[:],
				Nonce:          request.Nonce,
				CodeChallenge:  request.CodeChallenge,
				RequestedScope: request.Scope,
				ExpiresAt: pgtype.Timestamptz{
					Time:  now.Add(authorizationTransactionLifetime),
					Valid: true,
				},
			},
		)
	if err != nil {
		return PendingAuthorization{},
			fmt.Errorf("create authorization transaction: %w", err)
	}

	return PendingAuthorization{
		TransactionID:   transaction.ID,
		TenantID:        transaction.TenantID,
		ApplicationID:   transaction.ApplicationID,
		ApplicationName: application.Name,
		ClientID:        transaction.ClientID,
		RedirectURI:     transaction.RedirectUri,
		AccessMode:      application.AccessMode,
		RequestedScope:  transaction.RequestedScope,
		Nonce:           transaction.Nonce,
		CodeChallenge:   transaction.CodeChallenge,
		ExpiresAt:       transaction.ExpiresAt.Time,
		TenantSlug:      application.TenantSlug,
	}, nil
}

func (service *AuthorizationService) LoadAuthorization(
	ctx context.Context,
	transactionID pgtype.UUID,
	state string,
) (PendingAuthorization, error) {
	if service == nil ||
		service.queries == nil ||
		service.now == nil {
		return PendingAuthorization{},
			ErrInvalidAuthorizationServiceConfiguration
	}

	if !transactionID.Valid ||
		!validAuthorizationOpaqueValue(state) {
		return PendingAuthorization{},
			ErrAuthorizationTransactionNotFound
	}

	stateHash := sha256.Sum256([]byte(state))

	transaction, err :=
		service.queries.GetAuthorizationTransactionByIDAndStateHash(
			ctx,
			store.GetAuthorizationTransactionByIDAndStateHashParams{
				TransactionID: transactionID,
				StateHash:     stateHash[:],
			},
		)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PendingAuthorization{},
				ErrAuthorizationTransactionNotFound
		}

		return PendingAuthorization{},
			fmt.Errorf("load authorization transaction: %w", err)
	}

	if transaction.ConsumedAt.Valid {
		return PendingAuthorization{},
			ErrAuthorizationTransactionConsumed
	}

	if transaction.TenantStatus != "active" ||
		transaction.ApplicationStatus != "active" {
		return PendingAuthorization{}, ErrAuthorizationClientUnavailable
	}

	now := service.now().UTC()
	if !transaction.ExpiresAt.Valid ||
		!transaction.ExpiresAt.Time.After(now) {
		return PendingAuthorization{},
			ErrAuthorizationTransactionExpired
	}

	return PendingAuthorization{
		TransactionID:   transaction.ID,
		TenantID:        transaction.TenantID,
		ApplicationID:   transaction.ApplicationID,
		ApplicationName: transaction.ApplicationName,
		ClientID:        transaction.ClientID,
		RedirectURI:     transaction.RedirectUri,
		AccessMode:      transaction.AccessMode,
		RequestedScope:  transaction.RequestedScope,
		Nonce:           transaction.Nonce,
		CodeChallenge:   transaction.CodeChallenge,
		ExpiresAt:       transaction.ExpiresAt.Time,
		TenantSlug:      transaction.TenantSlug,
	}, nil
}

func newAuthorizationProtocolError(
	cause error,
	redirectURI string,
	values url.Values,
) *AuthorizationProtocolError {
	code := "invalid_request"

	switch {
	case errors.Is(cause, ErrUnsupportedResponseType):
		code = "unsupported_response_type"
	case errors.Is(cause, ErrInvalidAuthorizationScope):
		code = "invalid_scope"
	}

	state := ""
	if candidate, ok := requiredSingleton(values, "state"); ok &&
		validAuthorizationOpaqueValue(candidate) {
		state = candidate
	}

	return &AuthorizationProtocolError{
		Code:        code,
		RedirectURI: redirectURI,
		State:       state,
		cause:       cause,
	}
}
