package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type invitationTokenRequest struct {
	Token string `json:"token"`
}

type acceptInvitationRequest struct {
	Token       string `json:"token"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

type invitationPreviewResponse struct {
	TenantName           string `json:"tenant_name"`
	TenantSlug           string `json:"tenant_slug"`
	Email                string `json:"email"`
	RoleName             string `json:"role_name"`
	ExpiresAt            string `json:"expires_at"`
	AccountSetupRequired bool   `json:"account_setup_required"`
}

type acceptInvitationResponse struct {
	TenantID     string `json:"tenant_id"`
	MembershipID string `json:"membership_id"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

func (handler authHandler) previewMembershipInvitation(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var body invitationTokenRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	result, err :=
		handler.authentication.PreviewMembershipInvitation(
			request.Context(),
			strings.TrimSpace(body.Token),
		)
	if err != nil {
		writeMembershipInvitationError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		invitationPreviewResponse{
			TenantName: result.TenantName,
			TenantSlug: result.TenantSlug,
			Email:      result.Email,
			RoleName:   result.RoleName,
			ExpiresAt: result.ExpiresAt.UTC().Format(
				timeFormat,
			),
			AccountSetupRequired: result.AccountSetupRequired,
		},
	)
}

func (handler authHandler) acceptMembershipInvitation(
	writer http.ResponseWriter,
	request *http.Request,
) {
	var body acceptInvitationRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	result, err :=
		handler.authentication.AcceptMembershipInvitation(
			request.Context(),
			auth.AcceptMembershipInvitationInput{
				Token:       strings.TrimSpace(body.Token),
				DisplayName: body.DisplayName,
				Password:    body.Password,
			},
		)
	if err != nil {
		writeMembershipInvitationError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		acceptInvitationResponse{
			TenantID:     formatUUID(result.TenantID),
			MembershipID: formatUUID(result.MembershipID),
			UserID:       formatUUID(result.UserID),
			Email:        result.Email,
		},
	)
}

func writeMembershipInvitationError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		auth.ErrInvalidMembershipInvitationToken,
	):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid invitation link",
		)

	case errors.Is(
		err,
		auth.ErrMembershipInvitationExpired,
	):
		writeError(
			writer,
			http.StatusGone,
			"membership invitation expired",
		)

	case errors.Is(
		err,
		auth.ErrMembershipInvitationAccepted,
	):
		writeError(
			writer,
			http.StatusConflict,
			"membership invitation already accepted",
		)

	case errors.Is(
		err,
		auth.ErrInvitationAccountSetupRequired,
	):
		writeError(
			writer,
			http.StatusUnprocessableEntity,
			"account setup required",
		)

	case errors.Is(
		err,
		auth.ErrInvalidInvitationAccountSetup,
	):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid account setup",
		)

	case errors.Is(err, auth.ErrInvitedUserUnavailable):
		writeError(
			writer,
			http.StatusConflict,
			"invited user is unavailable",
		)

	case errors.Is(err, auth.ErrMemberAlreadyExists):
		writeError(
			writer,
			http.StatusConflict,
			"tenant membership already exists",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}
