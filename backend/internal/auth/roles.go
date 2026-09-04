package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	maxRoleNameLength        = 100
	maxRoleDescriptionLength = 300
)

var (
	ErrRoleManagementForbidden = errors.New(
		"role management forbidden",
	)
	ErrInvalidRole = errors.New(
		"invalid role",
	)
	ErrUnknownRolePermission = errors.New(
		"unknown role permission",
	)
	ErrRoleNameUnavailable = errors.New(
		"role name unavailable",
	)
	ErrRoleNotFound = errors.New(
		"role not found",
	)
	ErrSystemRoleImmutable = errors.New(
		"system role cannot be modified",
	)
)

type PermissionSummary struct {
	Permission  string
	Name        string
	Description string
}

type RoleSummary struct {
	RoleID      pgtype.UUID
	RoleKey     string
	Name        string
	Description string
	IsSystem    bool
	Permissions []string
}

type RoleListResult struct {
	Permissions []PermissionSummary
	Roles       []RoleSummary
}

type CreateRoleInput struct {
	Name        string
	Description string
	Permissions []string
}

type UpdateRoleInput struct {
	RoleID      pgtype.UUID
	Name        string
	Description string
	Permissions []string
}

func (service *Service) ListRoles(
	ctx context.Context,
	session SessionContext,
) (RoleListResult, error) {
	if !session.HasPermission(PermissionRoleRead) {
		return RoleListResult{},
			ErrRoleManagementForbidden
	}

	catalogRows, err :=
		service.queries.ListPermissionCatalog(ctx)
	if err != nil {
		return RoleListResult{}, fmt.Errorf(
			"list permission catalog: %w",
			err,
		)
	}

	roleRows, err :=
		service.queries.ListTenantRolesWithPermissions(
			ctx,
			session.TenantID,
		)
	if err != nil {
		return RoleListResult{}, fmt.Errorf(
			"list tenant roles: %w",
			err,
		)
	}

	permissions := make(
		[]PermissionSummary,
		0,
		len(catalogRows),
	)
	for _, row := range catalogRows {
		permissions = append(
			permissions,
			PermissionSummary{
				Permission:  row.Permission,
				Name:        row.Name,
				Description: row.Description,
			},
		)
	}

	roles := make([]RoleSummary, 0, len(roleRows))
	for _, row := range roleRows {
		roleKey := ""
		if row.RoleKey != nil {
			roleKey = *row.RoleKey
		}

		description := ""
		if row.Description != nil {
			description = *row.Description
		}

		roles = append(
			roles,
			RoleSummary{
				RoleID:      row.ID,
				RoleKey:     roleKey,
				Name:        row.Name,
				Description: description,
				IsSystem:    row.IsSystem,
				Permissions: row.Permissions,
			},
		)
	}

	return RoleListResult{
		Permissions: permissions,
		Roles:       roles,
	}, nil
}

func (service *Service) CreateRole(
	ctx context.Context,
	session SessionContext,
	input CreateRoleInput,
) (RoleSummary, error) {
	if !session.HasPermission(PermissionRoleManage) {
		return RoleSummary{},
			ErrRoleManagementForbidden
	}

	name, description, err := normalizeRoleMetadata(
		input.Name,
		input.Description,
	)
	if err != nil {
		return RoleSummary{}, err
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"begin role creation transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	permissions, err := validateRolePermissions(
		ctx,
		queries,
		input.Permissions,
	)
	if err != nil {
		return RoleSummary{}, err
	}

	role, err := queries.CreateCustomRole(
		ctx,
		store.CreateCustomRoleParams{
			TenantID:    session.TenantID,
			Name:        name,
			Description: description,
		},
	)
	if err != nil {
		return RoleSummary{},
			mapRolePersistenceError(
				"create custom role",
				err,
			)
	}

	if err := addRolePermissions(
		ctx,
		queries,
		session.TenantID,
		role.ID,
		permissions,
	); err != nil {
		return RoleSummary{}, err
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
			Type:              audit.EventRoleCreated,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "role",
			SubjectID:         role.ID,
			Metadata: audit.Metadata{
				"role_name":        role.Name,
				"permission_count": len(permissions),
			},
		},
	)
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"audit role creation: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return RoleSummary{}, fmt.Errorf(
			"commit role creation: %w",
			err,
		)
	}

	return summarizeStoredRole(role, permissions), nil
}

func (service *Service) UpdateRole(
	ctx context.Context,
	session SessionContext,
	input UpdateRoleInput,
) (RoleSummary, error) {
	if !session.HasPermission(PermissionRoleManage) {
		return RoleSummary{},
			ErrRoleManagementForbidden
	}

	if !input.RoleID.Valid {
		return RoleSummary{}, ErrInvalidRole
	}

	name, description, err := normalizeRoleMetadata(
		input.Name,
		input.Description,
	)
	if err != nil {
		return RoleSummary{}, err
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"begin role update transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)

	_, err = queries.GetCustomRoleForUpdate(
		ctx,
		store.GetCustomRoleForUpdateParams{
			TenantID: session.TenantID,
			RoleID:   input.RoleID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		existingRole, loadErr := queries.GetRoleByID(
			ctx,
			store.GetRoleByIDParams{
				TenantID: session.TenantID,
				RoleID:   input.RoleID,
			},
		)
		if errors.Is(loadErr, pgx.ErrNoRows) {
			return RoleSummary{}, ErrRoleNotFound
		}
		if loadErr != nil {
			return RoleSummary{}, fmt.Errorf(
				"load role after lock miss: %w",
				loadErr,
			)
		}
		if existingRole.IsSystem {
			return RoleSummary{},
				ErrSystemRoleImmutable
		}

		return RoleSummary{}, ErrRoleNotFound
	}
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"lock custom role: %w",
			err,
		)
	}

	previousPermissions, err := queries.ListRolePermissions(
		ctx,
		store.ListRolePermissionsParams{
			TenantID: session.TenantID,
			RoleID:   input.RoleID,
		},
	)
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"load existing role permissions: %w",
			err,
		)
	}

	permissions, err := validateRolePermissions(
		ctx,
		queries,
		input.Permissions,
	)
	if err != nil {
		return RoleSummary{}, err
	}

	role, err := queries.UpdateCustomRole(
		ctx,
		store.UpdateCustomRoleParams{
			Name:        name,
			Description: description,
			TenantID:    session.TenantID,
			RoleID:      input.RoleID,
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleSummary{}, ErrRoleNotFound
	}
	if err != nil {
		return RoleSummary{},
			mapRolePersistenceError(
				"update custom role",
				err,
			)
	}

	err = queries.DeleteRolePermissions(
		ctx,
		store.DeleteRolePermissionsParams{
			TenantID: session.TenantID,
			RoleID:   role.ID,
		},
	)
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"delete role permissions: %w",
			err,
		)
	}

	if err := addRolePermissions(
		ctx,
		queries,
		session.TenantID,
		role.ID,
		permissions,
	); err != nil {
		return RoleSummary{}, err
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
			Type:              audit.EventRoleUpdated,
			Outcome:           audit.OutcomeSuccess,
			SubjectType:       "role",
			SubjectID:         role.ID,
			Metadata: audit.Metadata{
				"role_name":                 role.Name,
				"previous_permission_count": len(previousPermissions),
				"permission_count":          len(permissions),
			},
		},
	)
	if err != nil {
		return RoleSummary{}, fmt.Errorf(
			"audit role update: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return RoleSummary{}, fmt.Errorf(
			"commit role update: %w",
			err,
		)
	}

	return summarizeStoredRole(role, permissions), nil
}

func normalizeRoleMetadata(
	name string,
	description string,
) (string, *string, error) {
	if !utf8.ValidString(name) ||
		!utf8.ValidString(description) {
		return "", nil, ErrInvalidRole
	}

	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)

	if utf8.RuneCountInString(name) < 1 ||
		utf8.RuneCountInString(name) >
			maxRoleNameLength ||
		utf8.RuneCountInString(description) >
			maxRoleDescriptionLength {
		return "", nil, ErrInvalidRole
	}

	if description == "" {
		return name, nil, nil
	}

	return name, &description, nil
}

func validateRolePermissions(
	ctx context.Context,
	queries *store.Queries,
	requested []string,
) ([]string, error) {
	catalog, err := queries.ListPermissionCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf(
			"load permission catalog: %w",
			err,
		)
	}

	known := make(map[string]struct{}, len(catalog))
	for _, permission := range catalog {
		known[permission.Permission] = struct{}{}
	}

	validated := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))

	for _, permission := range requested {
		if !utf8.ValidString(permission) ||
			permission != strings.TrimSpace(permission) {
			return nil, ErrUnknownRolePermission
		}

		if _, exists := known[permission]; !exists {
			return nil, ErrUnknownRolePermission
		}

		if _, duplicate := seen[permission]; duplicate {
			return nil, ErrInvalidRole
		}

		seen[permission] = struct{}{}
		validated = append(validated, permission)
	}

	sort.Strings(validated)
	return validated, nil
}

func addRolePermissions(
	ctx context.Context,
	queries *store.Queries,
	tenantID pgtype.UUID,
	roleID pgtype.UUID,
	permissions []string,
) error {
	for _, permission := range permissions {
		err := queries.AddRolePermission(
			ctx,
			store.AddRolePermissionParams{
				TenantID:   tenantID,
				RoleID:     roleID,
				Permission: permission,
			},
		)
		if err != nil {
			return fmt.Errorf(
				"add role permission: %w",
				err,
			)
		}
	}

	return nil
}

func summarizeStoredRole(
	role store.Role,
	permissions []string,
) RoleSummary {
	roleKey := ""
	if role.RoleKey != nil {
		roleKey = *role.RoleKey
	}

	description := ""
	if role.Description != nil {
		description = *role.Description
	}

	return RoleSummary{
		RoleID:      role.ID,
		RoleKey:     roleKey,
		Name:        role.Name,
		Description: description,
		IsSystem:    role.IsSystem,
		Permissions: permissions,
	}
}

func mapRolePersistenceError(
	action string,
	err error,
) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) &&
		postgresError.ConstraintName ==
			"roles_tenant_name_unique" {
		return ErrRoleNameUnavailable
	}

	return fmt.Errorf("%s: %w", action, err)
}
