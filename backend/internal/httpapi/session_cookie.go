package httpapi

import (
	"net/http"
	"time"
)

const sessionCookieName = "gatehouse_session"

type SessionCookie struct {
	secure bool
}

func NewSessionCookie(secure bool) SessionCookie {
	return SessionCookie{
		secure: secure,
	}
}

func (cookie SessionCookie) Read(request *http.Request) (string, error) {
	storedCookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}

	return storedCookie.Value, nil
}

func (cookie SessionCookie) Set(writer http.ResponseWriter, token string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/api/",
		Expires:  expiresAt.UTC(),
		MaxAge:   maxAge,
		Secure:   cookie.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (cookie SessionCookie) Clear(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/api/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   cookie.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
