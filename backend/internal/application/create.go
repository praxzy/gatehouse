package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	maxApplicationNameLength        = 100
	maxApplicationDescriptionLength = 300
	maxApplicationAccessRoles       = 100
)

func (service *Service) CreateApplication(
	ctx context.Context,
	session auth.SessionContext,
	input CreateApplicationInput,
) (CreateApplicationResult, error) {
	if !session.HasPermission(
		auth.PermissionApplicationManage,
	) {
		return CreateApplicationResult{},
			ErrApplicationManagementForbidden
	}

	name, description, err :=
		normalizeApplicationMetadata(
			input.Name,
			input.Description,
		)
	if err != nil {
		return CreateApplicationResult{}, err
	}

	if input.ClientType != ClientTypePublic &&
		input.ClientType != ClientTypeConfidential {
		return CreateApplicationResult{},
			ErrInvalidApplication
	}

	redirectURIs, err :=
		ValidateRedirectURIs(input.RedirectURIs)
	if err != nil {
		return CreateApplicationResult{}, err
	}

	allowedRoleIDs, err := validateAccessPolicy(
		input.AccessMode,
		input.AllowedRoleIDs,
	)
	if err != nil {
		return CreateApplicationResult{}, err
	}

	clientID, err := GenerateClientID()
	if err != nil {
		return CreateApplicationResult{}, err
	}

	var (
		rawClientSecret       string
		clientSecretHash      []byte
		clientSecretCreatedAt pgtype.Timestamptz
	)

	if input.ClientType == ClientTypeConfidential {
		rawClientSecret, clientSecretHash, err =
			GenerateClientSecret()
		if err != nil {
			return CreateApplicationResult{}, err
		}

		clientSecretCreatedAt = pgtype.Timestamptz{
			Time:  time.Now().UTC(),
			Valid: true,
		}
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return CreateApplicationResult{}, fmt.Errorf(
			"begin application creation transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	allowedRoles, err := validateApplicationRoles(
		ctx,
		queries,
		session.TenantID,
		allowedRoleIDs,
	)
	if err != nil {
		return CreateApplicationResult{}, err
	}

	created, err := queries.CreateApplication(
		ctx,
		store.CreateApplicationParams{
			TenantID:              session.TenantID,
			Name:                  name,
			Description:           description,
			ClientID:              clientID,
			ClientType:            string(input.ClientType),
			ClientSecretHash:      clientSecretHash,
			ClientSecretCreatedAt: clientSecretCreatedAt,
			AccessMode:            string(input.AccessMode),
		},
	)
	if err != nil {
		return CreateApplicationResult{},
			mapApplicationPersistenceError(
				"create application",
				err,
			)
	}

	createdRedirectURIs := make(
		[]RedirectURISummary,
		0,
		len(redirectURIs),
	)

	for _, redirectURI := range redirectURIs {
		row, err := queries.AddApplicationRedirectURI(
			ctx,
			store.AddApplicationRedirectURIParams{
				TenantID:      session.TenantID,
				ApplicationID: created.ID,
				Uri:           redirectURI,
			},
		)
		if err != nil {
			return CreateApplicationResult{},
				fmt.Errorf(
					"add application redirect URI: %w",
					err,
				)
		}

		createdRedirectURIs = append(
			createdRedirectURIs,
			RedirectURISummary{
				RedirectURIID: row.ID,
				URI:           row.Uri,
				CreatedAt:     row.CreatedAt.Time,
			},
		)
	}

	for _, role := range allowedRoles {
		err := queries.AddApplicationAccessRole(
			ctx,
			store.AddApplicationAccessRoleParams{
				TenantID:      session.TenantID,
				ApplicationID: created.ID,
				RoleID:        role.RoleID,
			},
		)
		if err != nil {
			return CreateApplicationResult{},
				fmt.Errorf(
					"add application access role: %w",
					err,
				)
		}
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			ApplicationID:     created.ID,
			SessionID:         session.SessionID,
			Type:              audit.EventApplicationCreated,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "application",
			SubjectID:         created.ID,
			Metadata: audit.Metadata{
				"client_type":        created.ClientType,
				"access_mode":        created.AccessMode,
				"redirect_uri_count": len(createdRedirectURIs),
				"allowed_role_count": len(allowedRoles),
			},
		},
	)
	if err != nil {
		return CreateApplicationResult{}, fmt.Errorf(
			"audit application creation: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return CreateApplicationResult{}, fmt.Errorf(
			"commit application creation: %w",
			err,
		)
	}

	return CreateApplicationResult{
		Application: ApplicationDetail{
			ApplicationID: created.ID,
			Name:          created.Name,
			Description:   stringValue(created.Description),
			ClientID:      created.ClientID,
			ClientType: ClientType(
				created.ClientType,
			),
			Status: created.Status,
			AccessMode: AccessMode(
				created.AccessMode,
			),
			CreatedAt:    created.CreatedAt.Time,
			UpdatedAt:    created.UpdatedAt.Time,
			RedirectURIs: createdRedirectURIs,
			AllowedRoles: allowedRoles,
		},
		ClientSecret: rawClientSecret,
	}, nil
}

func normalizeApplicationMetadata(
	name string,
	description string,
) (string, *string, error) {
	if !utf8.ValidString(name) ||
		!utf8.ValidString(description) {
		return "", nil, ErrInvalidApplication
	}

	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)

	if utf8.RuneCountInString(name) < 1 ||
		utf8.RuneCountInString(name) >
			maxApplicationNameLength ||
		utf8.RuneCountInString(description) >
			maxApplicationDescriptionLength {
		return "", nil, ErrInvalidApplication
	}

	if description == "" {
		return name, nil, nil
	}

	return name, &description, nil
}

func validateAccessPolicy(
	mode AccessMode,
	roleIDs []pgtype.UUID,
) ([]pgtype.UUID, error) {
	switch mode {
	case AccessModeAllActiveMembers:
		if len(roleIDs) != 0 {
			return nil, ErrInvalidApplication
		}

		return []pgtype.UUID{}, nil

	case AccessModeAllowedRoles:
		if len(roleIDs) == 0 ||
			len(roleIDs) > maxApplicationAccessRoles {
			return nil, ErrInvalidApplication
		}

	default:
		return nil, ErrInvalidApplication
	}

	validated := make(
		[]pgtype.UUID,
		0,
		len(roleIDs),
	)
	seen := make(
		map[pgtype.UUID]struct{},
		len(roleIDs),
	)

	for _, roleID := range roleIDs {
		if !roleID.Valid {
			return nil, ErrInvalidApplication
		}

		if _, duplicate := seen[roleID]; duplicate {
			return nil, ErrInvalidApplication
		}

		seen[roleID] = struct{}{}
		validated = append(validated, roleID)
	}

	return validated, nil
}

func validateApplicationRoles(
	ctx context.Context,
	queries *store.Queries,
	tenantID pgtype.UUID,
	roleIDs []pgtype.UUID,
) ([]ApplicationAccessRole, error) {
	roles := make(
		[]ApplicationAccessRole,
		0,
		len(roleIDs),
	)

	for _, roleID := range roleIDs {
		role, err := queries.GetRoleByID(
			ctx,
			store.GetRoleByIDParams{
				TenantID: tenantID,
				RoleID:   roleID,
			},
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrApplicationRoleNotFound
		}
		if err != nil {
			return nil, fmt.Errorf(
				"load application access role: %w",
				err,
			)
		}

		roleKey := ""
		if role.RoleKey != nil {
			roleKey = *role.RoleKey
		}

		roles = append(
			roles,
			ApplicationAccessRole{
				RoleID:   role.ID,
				RoleKey:  roleKey,
				Name:     role.Name,
				IsSystem: role.IsSystem,
			},
		)
	}

	return roles, nil
}

func mapApplicationPersistenceError(
	action string,
	err error,
) error {
	var postgresError *pgconn.PgError

	if errors.As(err, &postgresError) &&
		postgresError.ConstraintName ==
			"applications_client_id_unique" {
		return ErrApplicationClientIDUnavailable
	}

	return fmt.Errorf("%s: %w", action, err)
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}
