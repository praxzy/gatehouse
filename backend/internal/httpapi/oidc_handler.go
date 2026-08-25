package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
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

	ContinueAuthorization(
		ctx context.Context,
		transactionID pgtype.UUID,
		state string,
		session *oidc.AuthorizationSession,
	) (oidc.AuthorizationDecision, error)
}

type oidcHandler struct {
	metadata       OIDCMetadataService
	authorization  OIDCAuthorizationService
	authentication AuthenticationService
	sessionCookie  SessionCookie
}

type authorizationApplicationResponse struct {
	Name       string `json:"name"`
	ClientID   string `json:"client_id"`
	AccessMode string `json:"access_mode"`
}

type authorizationTransactionResponse struct {
	Status         string                           `json:"status"`
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

func (handler oidcHandler) authorize(
	writer http.ResponseWriter,
	request *http.Request,
) {
	authorization, err :=
		handler.authorization.BeginAuthorization(
			request.Context(),
			request.URL.Query(),
		)
	if err != nil {
		handler.writeAuthorizationError(writer, err)
		return
	}

	state, ok := authorizationQueryValue(
		request.URL.Query(),
		"state",
	)
	if !ok {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid authorization request",
		)
		return
	}

	handler.advanceAuthorization(
		writer,
		request,
		authorization.TransactionID,
		state,
	)
}

func (handler oidcHandler) continueAuthorization(
	writer http.ResponseWriter,
	request *http.Request,
) {
	transactionIDValue, ok := authorizationQueryValue(
		request.URL.Query(),
		"transaction_id",
	)
	if !ok {
		writeError(
			writer,
			http.StatusBadRequest,
			"authorization request is unavailable",
		)
		return
	}

	state, ok := authorizationQueryValue(
		request.URL.Query(),
		"state",
	)
	if !ok {
		writeError(
			writer,
			http.StatusBadRequest,
			"authorization request is unavailable",
		)
		return
	}

	transactionID, err := parseRequestUUID(
		transactionIDValue,
	)
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"authorization request is unavailable",
		)
		return
	}

	handler.advanceAuthorization(
		writer,
		request,
		transactionID,
		state,
	)
}

func (handler oidcHandler) advanceAuthorization(
	writer http.ResponseWriter,
	request *http.Request,
	transactionID pgtype.UUID,
	state string,
) {
	session, err := handler.resolveAuthorizationSession(
		writer,
		request,
	)
	if err != nil {
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal error",
		)
		return
	}

	decision, err :=
		handler.authorization.ContinueAuthorization(
			request.Context(),
			transactionID,
			state,
			session,
		)
	if err != nil {
		writeAuthorizationContinuationError(
			writer,
			err,
		)
		return
	}

	continuation := authorizationContinuationTarget(
		decision.Authorization.TransactionID,
		state,
	)

	switch decision.Step {
	case oidc.AuthorizationStepLoginRequired:
		redirectNoStore(
			writer,
			authorizationLoginTarget(
				decision.Authorization.TenantSlug,
				continuation,
				session != nil,
			),
		)

	case oidc.AuthorizationStepMFAEnrollmentRequired:
		redirectNoStore(
			writer,
			authorizationMFATarget(
				"/mfa/enroll",
				continuation,
			),
		)

	case oidc.AuthorizationStepMFAChallengeRequired:
		redirectNoStore(
			writer,
			authorizationMFATarget(
				"/mfa/challenge",
				continuation,
			),
		)

	case oidc.AuthorizationStepDenied:
		redirectAuthorizationError(
			writer,
			&oidc.AuthorizationProtocolError{
				Code:        "access_denied",
				RedirectURI: decision.Authorization.RedirectURI,
				State:       state,
			},
		)

	case oidc.AuthorizationStepGranted:
		writeAuthorizationGrant(
			writer,
			decision.Authorization,
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal error",
		)
	}
}

func (handler oidcHandler) resolveAuthorizationSession(
	writer http.ResponseWriter,
	request *http.Request,
) (*oidc.AuthorizationSession, error) {
	if handler.authentication == nil {
		return nil, nil
	}

	rawToken, err := handler.sessionCookie.Read(request)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	session, err := handler.authentication.ResolveSession(
		request.Context(),
		rawToken,
	)
	if errors.Is(err, auth.ErrInvalidSession) {
		handler.sessionCookie.Clear(writer)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &oidc.AuthorizationSession{
		SessionID:    session.SessionID,
		TenantID:     session.TenantID,
		MembershipID: session.MembershipID,
		UserID:       session.UserID,
	}, nil
}

func writeAuthorizationGrant(
	writer http.ResponseWriter,
	authorization oidc.PendingAuthorization,
) {
	writeJSON(
		writer,
		http.StatusOK,
		authorizationTransactionResponse{
			Status:        "granted",
			TransactionID: formatUUID(authorization.TransactionID),
			Application: authorizationApplicationResponse{
				Name:       authorization.ApplicationName,
				ClientID:   authorization.ClientID,
				AccessMode: authorization.AccessMode,
			},
			RequestedScope: authorization.RequestedScope,
			ExpiresAt: authorization.ExpiresAt.UTC().Format(
				timeFormat,
			),
		},
	)
}

func (handler oidcHandler) writeAuthorizationError(
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

func writeAuthorizationContinuationError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(
		err,
		oidc.ErrAuthorizationTransactionExpired,
	):
		writeError(
			writer,
			http.StatusGone,
			"authorization request expired",
		)

	case errors.Is(
		err,
		oidc.ErrAuthorizationTransactionNotFound,
	),
		errors.Is(
			err,
			oidc.ErrAuthorizationTransactionConsumed,
		),
		errors.Is(
			err,
			oidc.ErrAuthorizationClientUnavailable,
		):
		writeError(
			writer,
			http.StatusBadRequest,
			"authorization request is unavailable",
		)

	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal error",
		)
	}
}

func authorizationContinuationTarget(
	transactionID pgtype.UUID,
	state string,
) string {
	query := url.Values{
		"transaction_id": {
			formatUUID(transactionID),
		},
		"state": {state},
	}

	return "/oauth/authorize/continue?" +
		query.Encode()
}

func authorizationLoginTarget(
	tenantSlug string,
	returnTo string,
	force bool,
) string {
	query := url.Values{
		"tenant_slug": {tenantSlug},
		"return_to":   {returnTo},
	}

	if force {
		query.Set("force", "1")
	}

	return "/login?" + query.Encode()
}

func authorizationMFATarget(
	path string,
	returnTo string,
) string {
	query := url.Values{
		"return_to": {returnTo},
	}

	return path + "?" + query.Encode()
}

func authorizationQueryValue(
	values url.Values,
	name string,
) (string, bool) {
	items, exists := values[name]
	if !exists ||
		len(items) != 1 ||
		items[0] == "" {
		return "", false
	}

	return items[0], true
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

	redirectNoStore(
		writer,
		destination.String(),
	)
}

func redirectNoStore(
	writer http.ResponseWriter,
	location string,
) {
	writer.Header().Set(
		"Cache-Control",
		"no-store",
	)
	writer.Header().Set(
		"Location",
		location,
	)
	writer.WriteHeader(http.StatusFound)
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
