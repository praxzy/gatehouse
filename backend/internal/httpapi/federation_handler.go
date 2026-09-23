package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/praxzy/gatehouse/backend/internal/federation"
)

type FederationAuthorizationStarter interface {
	Begin(
		context.Context,
		federation.BeginAuthorizationInput,
	) (federation.BeginAuthorizationResult, error)
}

type FederationAuthorizationCompleter interface {
	Complete(
		context.Context,
		federation.CompleteAuthorizationInput,
	) (federation.CompleteAuthorizationResult, error)
}

type federationHandler struct {
	authorization FederationAuthorizationStarter
	callback      FederationAuthorizationCompleter
	sessionCookie SessionCookie
}

func (handler federationHandler) begin(
	writer http.ResponseWriter,
	request *http.Request,
) {
	tenantSlug := request.PathValue("tenantSlug")
	returnPath := "/"

	values := request.URL.Query()
	if supplied, exists := values["return_to"]; exists {
		if len(supplied) != 1 ||
			supplied[0] == "" {
			writeError(
				writer,
				http.StatusBadRequest,
				"invalid sign-in request",
			)
			return
		}

		returnPath = supplied[0]
	}

	result, err := handler.authorization.Begin(
		request.Context(),
		federation.BeginAuthorizationInput{
			TenantSlug: tenantSlug,
			ReturnPath: returnPath,
		},
	)

	switch {
	case errors.Is(
		err,
		federation.ErrInvalidBeginRequest,
	):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid sign-in request",
		)
		return

	case errors.Is(
		err,
		federation.ErrFederationUnavailable,
	):
		writeError(
			writer,
			http.StatusNotFound,
			"upstream sign-in is unavailable",
		)
		return

	case err != nil:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	redirectNoStore(
		writer,
		result.AuthorizationURL,
	)
}

func (handler federationHandler) complete(
	writer http.ResponseWriter,
	request *http.Request,
) {
	values := request.URL.Query()

	state, ok := authorizationQueryValue(
		values,
		"state",
	)
	if !ok {
		writeError(
			writer,
			http.StatusBadRequest,
			"sign-in request is unavailable",
		)
		return
	}

	code, codeExists, codeValid :=
		optionalSingleQueryValue(
			values,
			"code",
		)
	providerError, errorExists, errorValid :=
		optionalSingleQueryValue(
			values,
			"error",
		)

	if (codeExists && !codeValid) ||
		(errorExists && !errorValid) ||
		codeExists == errorExists {
		writeError(
			writer,
			http.StatusBadRequest,
			"sign-in request is unavailable",
		)
		return
	}

	previousSession := ""
	if rawToken, err :=
		handler.sessionCookie.Read(request); err == nil {
		previousSession = rawToken
	}

	result, err := handler.callback.Complete(
		request.Context(),
		federation.CompleteAuthorizationInput{
			State:           state,
			Code:            code,
			ProviderError:   providerError,
			PreviousSession: previousSession,
		},
	)

	switch {
	case errors.Is(
		err,
		federation.ErrInvalidAuthorizationCallback,
	):
		writeError(
			writer,
			http.StatusBadRequest,
			"sign-in request is unavailable",
		)
		return

	case errors.Is(
		err,
		federation.ErrUpstreamAuthorizationDenied,
	):
		writeError(
			writer,
			http.StatusForbidden,
			"sign-in was denied",
		)
		return

	case errors.Is(
		err,
		federation.ErrUpstreamIdentityNotMapped,
	):
		writeError(
			writer,
			http.StatusForbidden,
			"account is not authorized",
		)
		return

	case errors.Is(
		err,
		federation.ErrFederationUnavailable,
	):
		writeError(
			writer,
			http.StatusBadGateway,
			"upstream sign-in is unavailable",
		)
		return

	case err != nil:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
		return
	}

	handler.sessionCookie.Set(
		writer,
		result.Session.Token,
		result.Session.ExpiresAt,
	)

	redirectNoStore(
		writer,
		result.ReturnPath,
	)
}

func optionalSingleQueryValue(
	values map[string][]string,
	name string,
) (value string, exists bool, valid bool) {
	items, exists := values[name]
	if !exists {
		return "", false, true
	}

	if len(items) != 1 ||
		items[0] == "" {
		return "", true, false
	}

	return items[0], true, true
}
