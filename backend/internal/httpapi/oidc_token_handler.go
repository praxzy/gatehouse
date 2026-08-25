package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"

	"github.com/praxzy/gatehouse/backend/internal/oidc"
)

const maxTokenRequestBytes = 16 * 1024

type OIDCTokenService interface {
	ExchangeAuthorizationCode(
		ctx context.Context,
		values url.Values,
		authentication oidc.TokenClientAuthentication,
	) (oidc.TokenResult, error)
}

type oidcTokenHandler struct {
	tokens OIDCTokenService
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

type oauthErrorResponse struct {
	Error string `json:"error"`
}

func (handler oidcTokenHandler) exchange(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.RawQuery != "" {
		writeOAuthError(
			writer,
			http.StatusBadRequest,
			"invalid_request",
			false,
		)
		return
	}

	mediaType, _, err := mime.ParseMediaType(
		request.Header.Get("Content-Type"),
	)
	if err != nil ||
		mediaType !=
			"application/x-www-form-urlencoded" {
		writeOAuthError(
			writer,
			http.StatusBadRequest,
			"invalid_request",
			false,
		)
		return
	}

	request.Body = http.MaxBytesReader(
		writer,
		request.Body,
		maxTokenRequestBytes,
	)

	if err := request.ParseForm(); err != nil {
		writeOAuthError(
			writer,
			http.StatusBadRequest,
			"invalid_request",
			false,
		)
		return
	}

	clientAuthentication, ok :=
		tokenClientAuthentication(request)
	if !ok {
		writeOAuthError(
			writer,
			http.StatusUnauthorized,
			"invalid_client",
			true,
		)
		return
	}

	result, err :=
		handler.tokens.ExchangeAuthorizationCode(
			request.Context(),
			request.PostForm,
			clientAuthentication,
		)
	if err != nil {
		writeTokenServiceError(
			writer,
			err,
			clientAuthentication.Method ==
				oidc.TokenClientAuthenticationBasic,
		)
		return
	}

	writeTokenJSON(
		writer,
		http.StatusOK,
		tokenResponse{
			AccessToken: result.AccessToken,
			TokenType:   result.TokenType,
			ExpiresIn:   result.ExpiresIn,
			IDToken:     result.IDToken,
			Scope:       result.Scope,
		},
	)
}

func tokenClientAuthentication(
	request *http.Request,
) (oidc.TokenClientAuthentication, bool) {
	authorizationHeaders :=
		request.Header.Values("Authorization")

	if len(authorizationHeaders) == 0 {
		return oidc.TokenClientAuthentication{
			Method: oidc.TokenClientAuthenticationNone,
		}, true
	}

	if len(authorizationHeaders) != 1 {
		return oidc.TokenClientAuthentication{}, false
	}

	clientID, clientSecret, ok := request.BasicAuth()
	if !ok {
		return oidc.TokenClientAuthentication{}, false
	}

	return oidc.TokenClientAuthentication{
		Method:       oidc.TokenClientAuthenticationBasic,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, true
}

func writeTokenServiceError(
	writer http.ResponseWriter,
	err error,
	usedBasicAuthentication bool,
) {
	switch {
	case errors.Is(
		err,
		oidc.ErrInvalidTokenRequest,
	),
		errors.Is(
			err,
			oidc.ErrInvalidPKCEVerifier,
		):
		writeOAuthError(
			writer,
			http.StatusBadRequest,
			"invalid_request",
			false,
		)

	case errors.Is(
		err,
		oidc.ErrUnsupportedTokenGrantType,
	):
		writeOAuthError(
			writer,
			http.StatusBadRequest,
			"unsupported_grant_type",
			false,
		)

	case errors.Is(
		err,
		oidc.ErrInvalidTokenClient,
	):
		status := http.StatusBadRequest
		if usedBasicAuthentication {
			status = http.StatusUnauthorized
		}

		writeOAuthError(
			writer,
			status,
			"invalid_client",
			usedBasicAuthentication,
		)

	case errors.Is(
		err,
		oidc.ErrInvalidAuthorizationGrant,
	):
		writeOAuthError(
			writer,
			http.StatusBadRequest,
			"invalid_grant",
			false,
		)

	default:
		writeOAuthError(
			writer,
			http.StatusInternalServerError,
			"server_error",
			false,
		)
	}
}

func writeOAuthError(
	writer http.ResponseWriter,
	status int,
	code string,
	basicChallenge bool,
) {
	if basicChallenge {
		writer.Header().Set(
			"WWW-Authenticate",
			`Basic realm="Gatehouse token endpoint"`,
		)
	}

	writeTokenJSON(
		writer,
		status,
		oauthErrorResponse{
			Error: code,
		},
	)
}

func writeTokenJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {
	writer.Header().Set(
		"Content-Type",
		"application/json",
	)
	writer.Header().Set(
		"Cache-Control",
		"no-store",
	)
	writer.Header().Set(
		"Pragma",
		"no-cache",
	)
	writer.WriteHeader(status)

	_ = json.NewEncoder(writer).Encode(value)
}
