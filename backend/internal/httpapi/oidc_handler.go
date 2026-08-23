package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

const (
	discoveryCacheControl = "public, max-age=3600"
	jwksCacheControl      = "public, max-age=300, stale-while-revalidate=60"
)

type OIDCMetadataService interface {
	DiscoveryDocument() oidc.DiscoveryDocument
	JSONWebKeySet() oidc.JSONWebKeySet
}

type OIDCAuthorizationService interface {
	BeginAuthorization(
		ctx context.Context,
		values url.Values,
	) (oidc.PendingAuthorization, error)
}

type oidcHandler struct {
	metadata      OIDCMetadataService
	authorization OIDCAuthorizationService
}

type authorizationApplicationResponse struct {
	Name       string `json:"name"`
	ClientID   string `json:"client_id"`
	AccessMode string `json:"access_mode"`
}

type authorizationTransactionResponse struct {
	TransactionID  string                           `json:"transaction_id"`
	Application    authorizationApplicationResponse `json:"application"`
	RequestedScope []string                         `json:"requested_scope"`
	ExpiresAt      string                           `json:"expires_at"`
}

func (handler oidcHandler) discovery(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writePublicJSON(
		writer,
		http.StatusOK,
		discoveryCacheControl,
		handler.metadata.DiscoveryDocument(),
	)
}

func (handler oidcHandler) jwks(
	writer http.ResponseWriter,
	_ *http.Request,
) {
	writePublicJSON(
		writer,
		http.StatusOK,
		jwksCacheControl,
		handler.metadata.JSONWebKeySet(),
	)
}

func writePublicJSON(
	writer http.ResponseWriter,
	status int,
	cacheControl string,
	value any,
) {
	writer.Header().Set(
		"Content-Type",
		"application/json",
	)
	writer.Header().Set(
		"Cache-Control",
		cacheControl,
	)
	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(value)
}

func (handler oidcHandler) authorize(
	writer http.ResponseWriter,
	request *http.Request,
) {
	result, err := handler.authorization.BeginAuthorization(
		request.Context(),
		request.URL.Query(),
	)
	if err != nil {
		handler.writeAuthorizationError(writer, err)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		authorizationTransactionResponse{
			TransactionID: formatUUID(result.TransactionID),
			Application: authorizationApplicationResponse{
				Name:       result.ApplicationName,
				ClientID:   result.ClientID,
				AccessMode: result.AccessMode,
			},
			RequestedScope: result.RequestedScope,
			ExpiresAt: result.ExpiresAt.UTC().Format(
				timeFormat,
			),
		},
	)
}

func (
	handler oidcHandler,
) writeAuthorizationError(
	writer http.ResponseWriter,
	err error,
) {
	var protocolError *oidc.AuthorizationProtocolError
	if errors.As(err, &protocolError) {
		redirectAuthorizationError(
			writer,
			protocolError,
		)
		return
	}

	if errors.Is(
		err,
		oidc.ErrAuthorizationClientUnavailable,
	) {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid authorization request",
		)
		return
	}

	writeError(
		writer,
		http.StatusInternalServerError,
		"internal error",
	)
}

func redirectAuthorizationError(
	writer http.ResponseWriter,
	protocolError *oidc.AuthorizationProtocolError,
) {
	destination, err := url.Parse(
		protocolError.RedirectURI,
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid authorization request",
		)
		return
	}

	query := destination.Query()
	query.Set("error", protocolError.Code)

	if protocolError.State != "" {
		query.Set("state", protocolError.State)
	}

	destination.RawQuery = query.Encode()

	writer.Header().Set("Cache-Control", "no-store")
	http.Redirect(
		writer,
		&http.Request{},
		destination.String(),
		http.StatusFound,
	)
}
