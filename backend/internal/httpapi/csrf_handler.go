package httpapi

import (
	"net/http"
)

type csrfHandler struct {
	protector     *CSRFProtector
	sessionCookie SessionCookie
}

type csrfTokenResponse struct {
	Token string `json:"csrf_token"`
}

func (handler csrfHandler) token(
	writer http.ResponseWriter,
	request *http.Request,
) {
	sessionToken, err :=
		handler.sessionCookie.Read(request)
	if err != nil {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	token, err :=
		handler.protector.Token(sessionToken)
	if err != nil {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		csrfTokenResponse{
			Token: token,
		},
	)
}
