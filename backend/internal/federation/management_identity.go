package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var (
	ErrInvalidIdentityMapping = errors.New(
		"invalid upstream identity mapping",
	)
	ErrIdentityMappingNotFound = errors.New(
		"upstream identity mapping not found",
	)
	ErrIdentityMappingUnavailable = errors.New(
		"upstream identity mapping unavailable",
	)
	ErrIdentityMappingTargetNotFound = errors.New(
		"identity mapping membership not found",
	)
)

type CreateIdentityMappingInput struct {
	Subject      string
	MembershipID pgtype.UUID
}

type DeleteIdentityMappingInput struct {
	Subject string
}

type IdentityMappingSummary struct {
	Subject          string
	MembershipID     pgtype.UUID
	UserID           pgtype.UUID
	Email            string
	DisplayName      string
	MembershipStatus string
	CreatedAt        time.Time
}

func (service *ManagementService) ListIdentityMappings(
	ctx context.Context,
	session auth.SessionContext,
) ([]IdentityMappingSummary, error) {
	if !session.HasPermission(
		auth.PermissionFederationManage,
	) {
		return nil, ErrFederationManagementForbidden
	}

	connection, err :=
		service.queries.GetTenantUpstreamOIDCConnection(
			ctx,
			session.TenantID,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrFederationConnectionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf(
			"load upstream connection: %w",
			err,
		)
	}

	rows, err :=
		service.queries.ListTenantUpstreamOIDCIdentities(
			ctx,
			store.ListTenantUpstreamOIDCIdentitiesParams{
				TenantID:     session.TenantID,
				ConnectionID: connection.ID,
			},
		)
	if err != nil {
		return nil, fmt.Errorf(
			"list upstream identity mappings: %w",
			err,
		)
	}

	mappings := make(
		[]IdentityMappingSummary,
		0,
		len(rows),
	)

	for _, row := range rows {
		mappings = append(
			mappings,
			IdentityMappingSummary{
				Subject:          row.Subject,
				MembershipID:     row.MembershipID,
				UserID:           row.UserID,
				Email:            row.Email,
				DisplayName:      row.DisplayName,
				MembershipStatus: row.MembershipStatus,
				CreatedAt:        row.CreatedAt.Time,
			},
		)
	}

	return mappings, nil
}

func (service *ManagementService) CreateIdentityMapping(
	ctx context.Context,
	session auth.SessionContext,
	input CreateIdentityMappingInput,
) (IdentityMappingSummary, error) {
	if !session.HasPermission(
		auth.PermissionFederationManage,
	) {
		return IdentityMappingSummary{},
			ErrFederationManagementForbidden
	}

	if !input.MembershipID.Valid ||
		!validSensitiveValue(
			input.Subject,
			maxSubjectBytes,
		) {
		return IdentityMappingSummary{},
			ErrInvalidIdentityMapping
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return IdentityMappingSummary{}, fmt.Errorf(
			"begin identity mapping transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(
			context.Background(),
		)
	}()

	queries := service.queries.WithTx(
		transaction,
	)

	connection, err :=
		queries.GetTenantUpstreamOIDCConnectionForUpdate(
			ctx,
			session.TenantID,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityMappingSummary{},
			ErrFederationConnectionNotFound
	}
	if err != nil {
		return IdentityMappingSummary{}, fmt.Errorf(
			"lock upstream connection: %w",
			err,
		)
	}

	mapping, err :=
		queries.CreateUpstreamOIDCIdentity(
			ctx,
			store.CreateUpstreamOIDCIdentityParams{
				Subject:      input.Subject,
				MembershipID: input.MembershipID,
				TenantID:     session.TenantID,
				ConnectionID: connection.ID,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityMappingSummary{},
			ErrIdentityMappingTargetNotFound
	}
	if err != nil {
		return IdentityMappingSummary{},
			mapIdentityPersistenceError(
				"create upstream identity mapping",
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
			SessionID:         session.SessionID,
			Type: audit.
				EventFederationIdentityMapped,
			Outcome:     audit.OutcomeSuccess,
			SubjectType: "upstream_oidc_connection",
			SubjectID:   connection.ID,
			Metadata: audit.Metadata{
				"membership_id": formatFederationUUID(
					mapping.MembershipID,
				),
			},
		},
	)
	if err != nil {
		return IdentityMappingSummary{}, fmt.Errorf(
			"audit upstream identity mapping: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return IdentityMappingSummary{}, fmt.Errorf(
			"commit upstream identity mapping: %w",
			err,
		)
	}

	return IdentityMappingSummary{
		Subject:      mapping.Subject,
		MembershipID: mapping.MembershipID,
		CreatedAt:    mapping.CreatedAt.Time,
	}, nil
}

func (service *ManagementService) DeleteIdentityMapping(
	ctx context.Context,
	session auth.SessionContext,
	input DeleteIdentityMappingInput,
) error {
	if !session.HasPermission(
		auth.PermissionFederationManage,
	) {
		return ErrFederationManagementForbidden
	}

	if !validSensitiveValue(
		input.Subject,
		maxSubjectBytes,
	) {
		return ErrInvalidIdentityMapping
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return fmt.Errorf(
			"begin identity unmapping transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(
			context.Background(),
		)
	}()

	queries := service.queries.WithTx(
		transaction,
	)

	connection, err :=
		queries.GetTenantUpstreamOIDCConnectionForUpdate(
			ctx,
			session.TenantID,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrFederationConnectionNotFound
	}
	if err != nil {
		return fmt.Errorf(
			"lock upstream connection: %w",
			err,
		)
	}

	mapping, err :=
		queries.DeleteUpstreamOIDCIdentity(
			ctx,
			store.DeleteUpstreamOIDCIdentityParams{
				TenantID:     session.TenantID,
				ConnectionID: connection.ID,
				Subject:      input.Subject,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIdentityMappingNotFound
	}
	if err != nil {
		return fmt.Errorf(
			"delete upstream identity mapping: %w",
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
			SessionID:         session.SessionID,
			Type: audit.
				EventFederationIdentityUnmapped,
			Outcome:     audit.OutcomeSuccess,
			SubjectType: "upstream_oidc_connection",
			SubjectID:   connection.ID,
			Metadata: audit.Metadata{
				"membership_id": formatFederationUUID(
					mapping.MembershipID,
				),
			},
		},
	)
	if err != nil {
		return fmt.Errorf(
			"audit upstream identity removal: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf(
			"commit upstream identity removal: %w",
			err,
		)
	}

	return nil
}

func mapIdentityPersistenceError(
	action string,
	err error,
) error {
	var postgresError *pgconn.PgError

	if errors.As(err, &postgresError) {
		switch postgresError.ConstraintName {
		case "upstream_oidc_identities_pkey",
			"upstream_oidc_identities_membership_unique":
			return ErrIdentityMappingUnavailable
		}
	}

	return fmt.Errorf("%s: %w", action, err)
}

func formatFederationUUID(
	value pgtype.UUID,
) string {
	if !value.Valid {
		return ""
	}

	return uuid.UUID(value.Bytes).String()
}
