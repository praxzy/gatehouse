package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type inviteMemberRequest struct {
	Email  string `json:"email"`
	RoleID string `json:"role_id"`
}

type updateMemberRequest struct {
	RoleID *string `json:"role_id"`
	Status *string `json:"status"`
}

type inviteMemberResponse struct {
	InvitationID string `json:"invitation_id"`
	Email        string `json:"email"`
	RoleID       string `json:"role_id"`
	RoleName     string `json:"role_name"`
	ExpiresAt    string `json:"expires_at"`
}

type memberResponse struct {
	MembershipID string `json:"membership_id"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Status       string `json:"status"`
	RoleID       string `json:"role_id"`
	RoleKey      string `json:"role_key"`
	RoleName     string `json:"role_name"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type openInvitationResponse struct {
	InvitationID string `json:"invitation_id"`
	Email        string `json:"email"`
	RoleID       string `json:"role_id"`
	RoleName     string `json:"role_name"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	Expired      bool   `json:"expired"`
}

type memberRoleResponse struct {
	RoleID   string `json:"role_id"`
	RoleKey  string `json:"role_key"`
	RoleName string `json:"role_name"`
}

type memberListResponse struct {
	Members     []memberResponse         `json:"members"`
	Invitations []openInvitationResponse `json:"invitations"`
	Roles       []memberRoleResponse     `json:"roles"`
}

func (handler authHandler) listMembers(
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

	result, err := handler.authentication.ListMembers(
		request.Context(),
		session,
	)
	if err != nil {
		writeMemberManagementError(writer, err)
		return
	}

	response := memberListResponse{
		Members: make(
			[]memberResponse,
			0,
			len(result.Members),
		),
		Invitations: make(
			[]openInvitationResponse,
			0,
			len(result.Invitations),
		),
		Roles: make(
			[]memberRoleResponse,
			0,
			len(result.Roles),
		),
	}

	for _, member := range result.Members {
		response.Members = append(
			response.Members,
			memberResponse{
				MembershipID: formatUUID(
					member.MembershipID,
				),
				UserID:      formatUUID(member.UserID),
				Email:       member.Email,
				DisplayName: member.DisplayName,
				Status:      member.Status,
				RoleID:      formatUUID(member.RoleID),
				RoleKey:     member.RoleKey,
				RoleName:    member.RoleName,
				CreatedAt: member.CreatedAt.UTC().Format(
					timeFormat,
				),
				UpdatedAt: member.UpdatedAt.UTC().Format(
					timeFormat,
				),
			},
		)
	}

	for _, invitation := range result.Invitations {
		response.Invitations = append(
			response.Invitations,
			openInvitationResponse{
				InvitationID: formatUUID(
					invitation.InvitationID,
				),
				Email:    invitation.Email,
				RoleID:   formatUUID(invitation.RoleID),
				RoleName: invitation.RoleName,
				CreatedAt: invitation.CreatedAt.UTC().Format(
					timeFormat,
				),
				ExpiresAt: invitation.ExpiresAt.UTC().Format(
					timeFormat,
				),
				Expired: invitation.Expired,
			},
		)
	}

	for _, role := range result.Roles {
		response.Roles = append(
			response.Roles,
			memberRoleResponse{
				RoleID:   formatUUID(role.RoleID),
				RoleKey:  role.RoleKey,
				RoleName: role.RoleName,
			},
		)
	}

	writeJSON(writer, http.StatusOK, response)
}

func (handler authHandler) inviteMember(
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

	var body inviteMemberRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	roleID, err := parseRequestUUID(body.RoleID)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	result, err := handler.authentication.InviteMember(
		request.Context(),
		session,
		auth.InviteMemberInput{
			Email:  body.Email,
			RoleID: roleID,
		},
	)
	if err != nil {
		writeMemberManagementError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusCreated,
		inviteMemberResponse{
			InvitationID: formatUUID(
				result.InvitationID,
			),
			Email:    result.Email,
			RoleID:   formatUUID(result.RoleID),
			RoleName: result.RoleName,
			ExpiresAt: result.ExpiresAt.UTC().Format(
				timeFormat,
			),
		},
	)
}

func (handler authHandler) updateMember(
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

	membershipID, err := parseRequestUUID(
		chi.URLParam(request, "membershipID"),
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	var body updateMemberRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	var roleID pgtype.UUID
	if body.RoleID != nil {
		roleID, err = parseRequestUUID(*body.RoleID)
		if err != nil {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid request",
			)
			return
		}
	}

	status := ""
	if body.Status != nil {
		status = *body.Status
	}

	err = handler.authentication.UpdateMember(
		request.Context(),
		session,
		auth.UpdateMemberInput{
			MembershipID: membershipID,
			RoleID:       roleID,
			Status:       status,
		},
	)
	if err != nil {
		writeMemberManagementError(writer, err)
		return
	}

	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func parseRequestUUID(
	value string,
) (pgtype.UUID, error) {
	parsed, err := uuid.Parse(
		strings.TrimSpace(value),
	)
	if err != nil {
		return pgtype.UUID{}, err
	}

	return pgtype.UUID{
		Bytes: parsed,
		Valid: true,
	}, nil
}

func writeMemberManagementError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		auth.ErrMemberManagementForbidden,
	):
		writeError(
			writer,
			http.StatusForbidden,
			"member management forbidden",
		)

	case errors.Is(
		err,
		auth.ErrInvalidMemberInvitation,
	):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid member invitation",
		)

	case errors.Is(err, auth.ErrMemberAlreadyExists):
		writeError(
			writer,
			http.StatusConflict,
			"tenant membership already exists",
		)

	case errors.Is(
		err,
		auth.ErrInvitationRoleNotFound,
	),
		errors.Is(err, auth.ErrMemberRoleNotFound):
		writeError(
			writer,
			http.StatusNotFound,
			"member role not found",
		)

	case errors.Is(err, auth.ErrInvalidMemberUpdate):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid member update",
		)

	case errors.Is(err, auth.ErrMemberNotFound):
		writeError(
			writer,
			http.StatusNotFound,
			"member not found",
		)

	case errors.Is(err, auth.ErrFinalOwnerRequired):
		writeError(
			writer,
			http.StatusConflict,
			"tenant must retain an active owner",
		)

	case errors.Is(
		err,
		auth.ErrMembershipInvitationDelivery,
	):
		writeError(
			writer,
			http.StatusBadGateway,
			"invitation created but delivery failed",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}
