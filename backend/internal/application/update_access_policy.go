package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/praxzy/gatehouse/backend/internal/audit"
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

	currentApplication, err := queries.GetApplicationByID(
		ctx,
		store.GetApplicationByIDParams{
			TenantID:      session.TenantID,
			ApplicationID: input.ApplicationID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationAccessPolicy{}, ErrApplicationNotFound
	}
	if err != nil {
		return ApplicationAccessPolicy{}, fmt.Errorf(
			"load application before policy update: %w",
			err,
		)
	}

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

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			ApplicationID:     input.ApplicationID,
			SessionID:         session.SessionID,
			Type:              audit.EventApplicationPolicyUpdated,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "application",
			SubjectID:         input.ApplicationID,
			Metadata: audit.Metadata{
				"previous_access_mode": currentApplication.AccessMode,
				"new_access_mode":      updated.AccessMode,
				"allowed_role_count":   len(allowedRoles),
			},
		},
	)
	if err != nil {
		return ApplicationAccessPolicy{}, fmt.Errorf(
			"audit application access policy update: %w",
			err,
		)
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
