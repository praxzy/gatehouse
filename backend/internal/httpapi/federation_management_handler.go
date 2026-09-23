package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/federation"
)

type FederationManagementService interface {
	GetConnection(
		context.Context,
		auth.SessionContext,
	) (federation.ConnectionSummary, error)

	SaveConnection(
		context.Context,
		auth.SessionContext,
		federation.SaveConnectionInput,
	) (federation.ConnectionSummary, error)

	SetConnectionStatus(
		context.Context,
		auth.SessionContext,
		federation.ConnectionStatus,
	) (federation.ConnectionSummary, error)

	ListIdentityMappings(
		context.Context,
		auth.SessionContext,
	) ([]federation.IdentityMappingSummary, error)

	CreateIdentityMapping(
		context.Context,
		auth.SessionContext,
		federation.CreateIdentityMappingInput,
	) (federation.IdentityMappingSummary, error)

	DeleteIdentityMapping(
		context.Context,
		auth.SessionContext,
		federation.DeleteIdentityMappingInput,
	) error
}

type federationManagementHandler struct {
	management FederationManagementService
}

type saveFederationConnectionRequest struct {
	DisplayName  string `json:"display_name"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type updateFederationConnectionStatusRequest struct {
	Status string `json:"status"`
}

type createFederationIdentityMappingRequest struct {
	Subject      string `json:"subject"`
	MembershipID string `json:"membership_id"`
}

type deleteFederationIdentityMappingRequest struct {
	Subject string `json:"subject"`
}

type federationConnectionResponse struct {
	ConnectionID string `json:"connection_id"`
	DisplayName  string `json:"display_name"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type federationIdentityMappingResponse struct {
	Subject          string `json:"subject"`
	MembershipID     string `json:"membership_id"`
	UserID           string `json:"user_id,omitempty"`
	Email            string `json:"email,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	MembershipStatus string `json:"membership_status,omitempty"`
	CreatedAt        string `json:"created_at"`
}

type federationIdentityMappingsResponse struct {
	Mappings []federationIdentityMappingResponse `json:"mappings"`
}

func (handler federationManagementHandler) getConnection(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(
		request.Context(),
	)
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	connection, err :=
		handler.management.GetConnection(
			request.Context(),
			session,
		)
	if err != nil {
		writeFederationManagementError(
			writer,
			err,
		)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		federationConnectionView(connection),
	)
}

func (handler federationManagementHandler) saveConnection(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(
		request.Context(),
	)
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body saveFederationConnectionRequest
	if err := decodeJSON(
		writer,
		request,
		&body,
	); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	connection, err :=
		handler.management.SaveConnection(
			request.Context(),
			session,
			federation.SaveConnectionInput{
				DisplayName:  body.DisplayName,
				Issuer:       body.Issuer,
				ClientID:     body.ClientID,
				ClientSecret: body.ClientSecret,
			},
		)
	if err != nil {
		writeFederationManagementError(
			writer,
			err,
		)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		federationConnectionView(connection),
	)
}

func (handler federationManagementHandler) updateConnectionStatus(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(
		request.Context(),
	)
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body updateFederationConnectionStatusRequest
	if err := decodeJSON(
		writer,
		request,
		&body,
	); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	connection, err :=
		handler.management.SetConnectionStatus(
			request.Context(),
			session,
			federation.ConnectionStatus(
				body.Status,
			),
		)
	if err != nil {
		writeFederationManagementError(
			writer,
			err,
		)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		federationConnectionView(connection),
	)
}

func (handler federationManagementHandler) listIdentityMappings(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(
		request.Context(),
	)
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	mappings, err :=
		handler.management.ListIdentityMappings(
			request.Context(),
			session,
		)
	if err != nil {
		writeFederationManagementError(
			writer,
			err,
		)
		return
	}

	response := make(
		[]federationIdentityMappingResponse,
		0,
		len(mappings),
	)

	for _, mapping := range mappings {
		response = append(
			response,
			federationIdentityMappingView(
				mapping,
			),
		)
	}

	writeJSON(
		writer,
		http.StatusOK,
		federationIdentityMappingsResponse{
			Mappings: response,
		},
	)
}

func (handler federationManagementHandler) createIdentityMapping(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(
		request.Context(),
	)
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body createFederationIdentityMappingRequest
	if err := decodeJSON(
		writer,
		request,
		&body,
	); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	membershipID, err := parseRequestUUID(
		body.MembershipID,
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid identity mapping",
		)
		return
	}

	mapping, err :=
		handler.management.CreateIdentityMapping(
			request.Context(),
			session,
			federation.CreateIdentityMappingInput{
				Subject:      body.Subject,
				MembershipID: membershipID,
			},
		)
	if err != nil {
		writeFederationManagementError(
			writer,
			err,
		)
		return
	}

	writeJSON(
		writer,
		http.StatusCreated,
		federationIdentityMappingView(
			mapping,
		),
	)
}

func (handler federationManagementHandler) deleteIdentityMapping(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(
		request.Context(),
	)
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	var body deleteFederationIdentityMappingRequest
	if err := decodeJSON(
		writer,
		request,
		&body,
	); err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid request",
		)
		return
	}

	err := handler.management.DeleteIdentityMapping(
		request.Context(),
		session,
		federation.DeleteIdentityMappingInput{
			Subject: body.Subject,
		},
	)
	if err != nil {
		writeFederationManagementError(
			writer,
			err,
		)
		return
	}

	writer.WriteHeader(http.StatusNoContent)
}

func federationConnectionView(
	connection federation.ConnectionSummary,
) federationConnectionResponse {
	return federationConnectionResponse{
		ConnectionID: formatUUID(
			connection.ConnectionID,
		),
		DisplayName: connection.DisplayName,
		Issuer:      connection.Issuer,
		ClientID:    connection.ClientID,
		Status:      string(connection.Status),
		CreatedAt: connection.CreatedAt.
			UTC().
			Format(timeFormat),
		UpdatedAt: connection.UpdatedAt.
			UTC().
			Format(timeFormat),
	}
}

func federationIdentityMappingView(
	mapping federation.IdentityMappingSummary,
) federationIdentityMappingResponse {
	return federationIdentityMappingResponse{
		Subject: mapping.Subject,
		MembershipID: formatUUID(
			mapping.MembershipID,
		),
		UserID:           formatUUID(mapping.UserID),
		Email:            mapping.Email,
		DisplayName:      mapping.DisplayName,
		MembershipStatus: mapping.MembershipStatus,
		CreatedAt: mapping.CreatedAt.
			UTC().
			Format(timeFormat),
	}
}

func writeFederationManagementError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		federation.
			ErrFederationManagementForbidden,
	):
		writeError(
			writer,
			http.StatusForbidden,
			"insufficient permissions",
		)

	case errors.Is(
		err,
		federation.
			ErrInvalidFederationConnection,
	),
		errors.Is(
			err,
			federation.
				ErrInvalidIdentityMapping,
		):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid federation configuration",
		)

	case errors.Is(
		err,
		federation.
			ErrFederationConnectionNotFound,
	),
		errors.Is(
			err,
			federation.
				ErrIdentityMappingNotFound,
		),
		errors.Is(
			err,
			federation.
				ErrIdentityMappingTargetNotFound,
		):
		writeError(
			writer,
			http.StatusNotFound,
			"federation resource not found",
		)

	case errors.Is(
		err,
		federation.
			ErrIdentityMappingUnavailable,
	):
		writeError(
			writer,
			http.StatusConflict,
			"identity mapping already exists",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}
