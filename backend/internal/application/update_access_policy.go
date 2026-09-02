package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

func (service *Service) UpdateApplicationAccessPolicy(
	ctx context.Context,
	session auth.SessionContext,
	input UpdateApplicationAccessPolicyInput,
) (ApplicationAccessPolicy, error) {
	if !session.HasPermission(auth.PermissionApplicationManage) {
		return ApplicationAccessPolicy{},
			ErrApplicationManagementForbidden
	}

	if !input.ApplicationID.Valid {
		return ApplicationAccessPolicy{}, ErrInvalidApplication
	}

	allowedRoleIDs, err := validateAccessPolicy(
		input.AccessMode,
		input.AllowedRoleIDs,
	)
	if err != nil {
		return ApplicationAccessPolicy{}, err
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ApplicationAccessPolicy{}, fmt.Errorf(
			"begin application access policy transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	updated, err := queries.UpdateApplicationAccessMode(
		ctx,
		store.UpdateApplicationAccessModeParams{
			AccessMode:    string(input.AccessMode),
			TenantID:      session.TenantID,
			ApplicationID: input.ApplicationID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationAccessPolicy{}, ErrApplicationNotFound
	}
	if err != nil {
		return ApplicationAccessPolicy{}, fmt.Errorf(
			"update application access mode: %w",
			err,
		)
	}

	allowedRoles, err := validateApplicationRoles(
		ctx,
		queries,
		session.TenantID,
		allowedRoleIDs,
	)
	if err != nil {
		return ApplicationAccessPolicy{}, err
	}

	if err := queries.DeleteApplicationAccessRoles(
		ctx,
		store.DeleteApplicationAccessRolesParams{
			TenantID:      session.TenantID,
			ApplicationID: input.ApplicationID,
		},
	); err != nil {
		return ApplicationAccessPolicy{}, fmt.Errorf(
			"delete application access roles: %w",
			err,
		)
	}

	for _, role := range allowedRoles {
		if err := queries.AddApplicationAccessRole(
			ctx,
			store.AddApplicationAccessRoleParams{
				TenantID:      session.TenantID,
				ApplicationID: input.ApplicationID,
				RoleID:        role.RoleID,
			},
		); err != nil {
			return ApplicationAccessPolicy{}, fmt.Errorf(
				"add application access role: %w",
				err,
			)
		}
	}

	if err := transaction.Commit(ctx); err != nil {
		return ApplicationAccessPolicy{}, fmt.Errorf(
			"commit application access policy: %w",
			err,
		)
	}

	return ApplicationAccessPolicy{
		AccessMode:   AccessMode(updated.AccessMode),
		AllowedRoles: allowedRoles,
		UpdatedAt:    updated.UpdatedAt.Time,
	}, nil
}
