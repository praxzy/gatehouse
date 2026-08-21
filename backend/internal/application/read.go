package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

func (service *Service) ListApplications(
	ctx context.Context,
	session auth.SessionContext,
) ([]ApplicationSummary, error) {
	if !session.HasPermission(
		auth.PermissionApplicationRead,
	) {
		return nil, ErrApplicationReadForbidden
	}

	rows, err := service.queries.ListApplications(
		ctx,
		session.TenantID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list applications: %w",
			err,
		)
	}

	applications := make(
		[]ApplicationSummary,
		0,
		len(rows),
	)

	for _, row := range rows {
		applications = append(
			applications,
			ApplicationSummary{
				ApplicationID: row.ID,
				Name:          row.Name,
				Description: stringValue(
					row.Description,
				),
				ClientID: row.ClientID,
				ClientType: ClientType(
					row.ClientType,
				),
				Status: row.Status,
				AccessMode: AccessMode(
					row.AccessMode,
				),
				RedirectURICount: row.RedirectUriCount,
				AllowedRoleCount: row.AllowedRoleCount,
				CreatedAt:        row.CreatedAt.Time,
				UpdatedAt:        row.UpdatedAt.Time,
			},
		)
	}

	return applications, nil
}

func (service *Service) GetApplication(
	ctx context.Context,
	session auth.SessionContext,
	applicationID pgtype.UUID,
) (ApplicationDetail, error) {
	if !session.HasPermission(
		auth.PermissionApplicationRead,
	) {
		return ApplicationDetail{},
			ErrApplicationReadForbidden
	}

	if !applicationID.Valid {
		return ApplicationDetail{},
			ErrInvalidApplication
	}

	row, err := service.queries.GetApplicationByID(
		ctx,
		store.GetApplicationByIDParams{
			TenantID:      session.TenantID,
			ApplicationID: applicationID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ApplicationDetail{},
			ErrApplicationNotFound
	}
	if err != nil {
		return ApplicationDetail{}, fmt.Errorf(
			"get application: %w",
			err,
		)
	}

	redirectRows, err :=
		service.queries.ListApplicationRedirectURIs(
			ctx,
			store.ListApplicationRedirectURIsParams{
				TenantID:      session.TenantID,
				ApplicationID: applicationID,
			},
		)
	if err != nil {
		return ApplicationDetail{}, fmt.Errorf(
			"list application redirect URIs: %w",
			err,
		)
	}

	redirectURIs := make(
		[]RedirectURISummary,
		0,
		len(redirectRows),
	)
	for _, redirectRow := range redirectRows {
		redirectURIs = append(
			redirectURIs,
			RedirectURISummary{
				RedirectURIID: redirectRow.ID,
				URI:           redirectRow.Uri,
				CreatedAt:     redirectRow.CreatedAt.Time,
			},
		)
	}

	roleRows, err :=
		service.queries.ListApplicationAccessRoles(
			ctx,
			store.ListApplicationAccessRolesParams{
				TenantID:      session.TenantID,
				ApplicationID: applicationID,
			},
		)
	if err != nil {
		return ApplicationDetail{}, fmt.Errorf(
			"list application access roles: %w",
			err,
		)
	}

	allowedRoles := make(
		[]ApplicationAccessRole,
		0,
		len(roleRows),
	)
	for _, roleRow := range roleRows {
		roleKey := ""
		if roleRow.RoleKey != nil {
			roleKey = *roleRow.RoleKey
		}

		allowedRoles = append(
			allowedRoles,
			ApplicationAccessRole{
				RoleID:   roleRow.RoleID,
				RoleKey:  roleKey,
				Name:     roleRow.Name,
				IsSystem: roleRow.IsSystem,
			},
		)
	}

	return ApplicationDetail{
		ApplicationID: row.ID,
		Name:          row.Name,
		Description: stringValue(
			row.Description,
		),
		ClientID: row.ClientID,
		ClientType: ClientType(
			row.ClientType,
		),
		Status: row.Status,
		AccessMode: AccessMode(
			row.AccessMode,
		),
		CreatedAt:    row.CreatedAt.Time,
		UpdatedAt:    row.UpdatedAt.Time,
		RedirectURIs: redirectURIs,
		AllowedRoles: allowedRoles,
	}, nil
}
