package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/application"
	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type ApplicationService interface {
	ListApplications(
		ctx context.Context,
		session auth.SessionContext,
	) ([]application.ApplicationSummary, error)

	CreateApplication(
		ctx context.Context,
		session auth.SessionContext,
		input application.CreateApplicationInput,
	) (application.CreateApplicationResult, error)

	GetApplication(
		ctx context.Context,
		session auth.SessionContext,
		applicationID pgtype.UUID,
	) (application.ApplicationDetail, error)

	UpdateApplicationAccessPolicy(
		ctx context.Context,
		session auth.SessionContext,
		input application.UpdateApplicationAccessPolicyInput,
	) (application.ApplicationAccessPolicy, error)
}

type applicationHandler struct {
	applications ApplicationService
}

type createApplicationRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	ClientType     string   `json:"client_type"`
	RedirectURIs   []string `json:"redirect_uris"`
	AccessMode     string   `json:"access_mode"`
	AllowedRoleIDs []string `json:"allowed_role_ids"`
}

type updateApplicationAccessPolicyRequest struct {
	AccessMode     string   `json:"access_mode"`
	AllowedRoleIDs []string `json:"allowed_role_ids"`
}

type applicationAccessPolicyResponse struct {
	AccessMode   string                          `json:"access_mode"`
	AllowedRoles []applicationAccessRoleResponse `json:"allowed_roles"`
	UpdatedAt    string                          `json:"updated_at"`
}

type applicationSummaryResponse struct {
	ApplicationID    string `json:"application_id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	ClientID         string `json:"client_id"`
	ClientType       string `json:"client_type"`
	Status           string `json:"status"`
	AccessMode       string `json:"access_mode"`
	RedirectURICount int32  `json:"redirect_uri_count"`
	AllowedRoleCount int32  `json:"allowed_role_count"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type applicationListResponse struct {
	Applications []applicationSummaryResponse `json:"applications"`
}

type applicationRedirectURIResponse struct {
	RedirectURIID string `json:"redirect_uri_id"`
	URI           string `json:"uri"`
	CreatedAt     string `json:"created_at"`
}

type applicationAccessRoleResponse struct {
	RoleID   string `json:"role_id"`
	RoleKey  string `json:"role_key,omitempty"`
	Name     string `json:"name"`
	IsSystem bool   `json:"is_system"`
}

type applicationDetailResponse struct {
	ApplicationID string                           `json:"application_id"`
	Name          string                           `json:"name"`
	Description   string                           `json:"description"`
	ClientID      string                           `json:"client_id"`
	ClientType    string                           `json:"client_type"`
	Status        string                           `json:"status"`
	AccessMode    string                           `json:"access_mode"`
	CreatedAt     string                           `json:"created_at"`
	UpdatedAt     string                           `json:"updated_at"`
	RedirectURIs  []applicationRedirectURIResponse `json:"redirect_uris"`
	AllowedRoles  []applicationAccessRoleResponse  `json:"allowed_roles"`
}

type createApplicationResponse struct {
	Application  applicationDetailResponse `json:"application"`
	ClientSecret string                    `json:"client_secret,omitempty"`
}

func (handler applicationHandler) listApplications(
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

	applications, err := handler.applications.ListApplications(
		request.Context(),
		session,
	)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}

	response := applicationListResponse{
		Applications: make(
			[]applicationSummaryResponse,
			0,
			len(applications),
		),
	}

	for _, item := range applications {
		response.Applications = append(
			response.Applications,
			formatApplicationSummary(item),
		)
	}

	writeJSON(writer, http.StatusOK, response)
}

func (handler applicationHandler) createApplication(
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

	var body createApplicationRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	allowedRoleIDs := make(
		[]pgtype.UUID,
		0,
		len(body.AllowedRoleIDs),
	)

	for _, value := range body.AllowedRoleIDs {
		roleID, err := parseRequestUUID(value)
		if err != nil {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid application",
			)
			return
		}

		allowedRoleIDs = append(allowedRoleIDs, roleID)
	}

	result, err := handler.applications.CreateApplication(
		request.Context(),
		session,
		application.CreateApplicationInput{
			Name:           body.Name,
			Description:    body.Description,
			ClientType:     application.ClientType(body.ClientType),
			RedirectURIs:   body.RedirectURIs,
			AccessMode:     application.AccessMode(body.AccessMode),
			AllowedRoleIDs: allowedRoleIDs,
		},
	)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusCreated,
		createApplicationResponse{
			Application: formatApplicationDetail(
				result.Application,
			),
			ClientSecret: result.ClientSecret,
		},
	)
}

func (handler applicationHandler) getApplication(
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

	applicationID, err := parseRequestUUID(
		chi.URLParam(request, "applicationID"),
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid application",
		)
		return
	}

	result, err := handler.applications.GetApplication(
		request.Context(),
		session,
		applicationID,
	)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		formatApplicationDetail(result),
	)
}

func formatApplicationSummary(
	value application.ApplicationSummary,
) applicationSummaryResponse {
	return applicationSummaryResponse{
		ApplicationID:    formatUUID(value.ApplicationID),
		Name:             value.Name,
		Description:      value.Description,
		ClientID:         value.ClientID,
		ClientType:       string(value.ClientType),
		Status:           value.Status,
		AccessMode:       string(value.AccessMode),
		RedirectURICount: value.RedirectURICount,
		AllowedRoleCount: value.AllowedRoleCount,
		CreatedAt:        value.CreatedAt.Format(timeFormat),
		UpdatedAt:        value.UpdatedAt.Format(timeFormat),
	}
}

func formatApplicationDetail(
	value application.ApplicationDetail,
) applicationDetailResponse {
	redirectURIs := make(
		[]applicationRedirectURIResponse,
		0,
		len(value.RedirectURIs),
	)

	for _, redirectURI := range value.RedirectURIs {
		redirectURIs = append(
			redirectURIs,
			applicationRedirectURIResponse{
				RedirectURIID: formatUUID(
					redirectURI.RedirectURIID,
				),
				URI: redirectURI.URI,
				CreatedAt: redirectURI.CreatedAt.Format(
					timeFormat,
				),
			},
		)
	}

	allowedRoles := make(
		[]applicationAccessRoleResponse,
		0,
		len(value.AllowedRoles),
	)

	for _, role := range value.AllowedRoles {
		allowedRoles = append(
			allowedRoles,
			applicationAccessRoleResponse{
				RoleID:   formatUUID(role.RoleID),
				RoleKey:  role.RoleKey,
				Name:     role.Name,
				IsSystem: role.IsSystem,
			},
		)
	}

	return applicationDetailResponse{
		ApplicationID: formatUUID(value.ApplicationID),
		Name:          value.Name,
		Description:   value.Description,
		ClientID:      value.ClientID,
		ClientType:    string(value.ClientType),
		Status:        value.Status,
		AccessMode:    string(value.AccessMode),
		CreatedAt:     value.CreatedAt.Format(timeFormat),
		UpdatedAt:     value.UpdatedAt.Format(timeFormat),
		RedirectURIs:  redirectURIs,
		AllowedRoles:  allowedRoles,
	}
}

func writeApplicationError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		application.ErrApplicationReadForbidden,
	),
		errors.Is(
			err,
			application.ErrApplicationManagementForbidden,
		):
		writeError(
			writer,
			http.StatusForbidden,
			"application access forbidden",
		)

	case errors.Is(
		err,
		application.ErrApplicationNotFound,
	):
		writeError(
			writer,
			http.StatusNotFound,
			"application not found",
		)

	case errors.Is(
		err,
		application.ErrApplicationClientIDUnavailable,
	):
		writeError(
			writer,
			http.StatusConflict,
			"application client ID unavailable",
		)
	case errors.Is(
		err,
		application.ErrInvalidApplication,
	),
		errors.Is(
			err,
			application.ErrInvalidRedirectURI,
		),
		errors.Is(
			err,
			application.ErrDuplicateRedirectURI,
		),
		errors.Is(
			err,
			application.ErrApplicationRoleNotFound,
		):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid application",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}

func (handler applicationHandler) updateApplicationAccessPolicy(
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
	}

	applicationID, err := parseRequestUUID(
		chi.URLParam(request, "applicationID"),
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid application",
		)
		return
	}

	var body updateApplicationAccessPolicyRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	allowedRoleIDs := make(
		[]pgtype.UUID,
		0,
		len(body.AllowedRoleIDs),
	)

	for _, value := range body.AllowedRoleIDs {
		roleID, err := parseRequestUUID(value)
		if err != nil {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid application",
			)
			return
		}

		allowedRoleIDs = append(allowedRoleIDs, roleID)
	}

	result, err := handler.applications.UpdateApplicationAccessPolicy(
		request.Context(),
		session,
		application.UpdateApplicationAccessPolicyInput{
			ApplicationID: applicationID,
			AccessMode: application.AccessMode(
				body.AccessMode,
			),
			AllowedRoleIDs: allowedRoleIDs,
		},
	)
	if err != nil {
		writeApplicationError(writer, err)
		return
	}

	allowedRoles := make(
		[]applicationAccessRoleResponse,
		0,
		len(result.AllowedRoles),
	)

	for _, role := range result.AllowedRoles {
		allowedRoles = append(
			allowedRoles,
			applicationAccessRoleResponse{
				RoleID:   formatUUID(role.RoleID),
				RoleKey:  role.RoleKey,
				Name:     role.Name,
				IsSystem: role.IsSystem,
			},
		)
	}

	writeJSON(
		writer,
		http.StatusOK,
		applicationAccessPolicyResponse{
			AccessMode:   string(result.AccessMode),
			AllowedRoles: allowedRoles,
			UpdatedAt:    result.UpdatedAt.Format(timeFormat),
		},
	)
}
