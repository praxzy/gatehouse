package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type roleWriteRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type permissionResponse struct {
	Permission  string `json:"permission"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type roleResponse struct {
	RoleID      string   `json:"role_id"`
	RoleKey     string   `json:"role_key,omitempty"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
}

type roleListResponse struct {
	Permissions []permissionResponse `json:"permissions"`
	Roles       []roleResponse       `json:"roles"`
}

func (handler authHandler) listRoles(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	result, err := handler.authentication.ListRoles(
		request.Context(),
		session,
	)
	if err != nil {
		writeRoleManagementError(writer, err)
		return
	}

	response := roleListResponse{
		Permissions: make(
			[]permissionResponse,
			0,
			len(result.Permissions),
		),
		Roles: make(
			[]roleResponse,
			0,
			len(result.Roles),
		),
	}

	for _, permission := range result.Permissions {
		response.Permissions = append(
			response.Permissions,
			permissionResponse{
				Permission:  permission.Permission,
				Name:        permission.Name,
				Description: permission.Description,
			},
		)
	}

	for _, role := range result.Roles {
		response.Roles = append(
			response.Roles,
			formatRoleResponse(role),
		)
	}

	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, response)
}

func (handler authHandler) createRole(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body roleWriteRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	result, err := handler.authentication.CreateRole(
		request.Context(),
		session,
		auth.CreateRoleInput{
			Name:        body.Name,
			Description: body.Description,
			Permissions: body.Permissions,
		},
	)
	if err != nil {
		writeRoleManagementError(writer, err)
		return
	}

	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(
		writer,
		http.StatusCreated,
		formatRoleResponse(result),
	)
}

func (handler authHandler) updateRole(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	roleID, err := parseRequestUUID(
		chi.URLParam(request, "roleID"),
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	var body roleWriteRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	result, err := handler.authentication.UpdateRole(
		request.Context(),
		session,
		auth.UpdateRoleInput{
			RoleID:      roleID,
			Name:        body.Name,
			Description: body.Description,
			Permissions: body.Permissions,
		},
	)
	if err != nil {
		writeRoleManagementError(writer, err)
		return
	}

	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(
		writer,
		http.StatusOK,
		formatRoleResponse(result),
	)
}

func formatRoleResponse(
	role auth.RoleSummary,
) roleResponse {
	return roleResponse{
		RoleID:      formatUUID(role.RoleID),
		RoleKey:     role.RoleKey,
		Name:        role.Name,
		Description: role.Description,
		IsSystem:    role.IsSystem,
		Permissions: role.Permissions,
	}
}

func writeRoleManagementError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		auth.ErrRoleManagementForbidden,
	):
		writeError(
			writer,
			http.StatusForbidden,
			"role management forbidden",
		)

	case errors.Is(err, auth.ErrInvalidRole),
		errors.Is(
			err,
			auth.ErrUnknownRolePermission,
		):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid role",
		)

	case errors.Is(
		err,
		auth.ErrRoleNameUnavailable,
	):
		writeError(
			writer,
			http.StatusConflict,
			"role name unavailable",
		)

	case errors.Is(err, auth.ErrRoleNotFound):
		writeError(
			writer,
			http.StatusNotFound,
			"role not found",
		)

	case errors.Is(
		err,
		auth.ErrSystemRoleImmutable,
	):
		writeError(
			writer,
			http.StatusConflict,
			"system role cannot be modified",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}
