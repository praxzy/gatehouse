package httpapp

import (
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"time"

	"github.com/praxzy/gatehouse/examples/employee-portal/internal/oidcclient"
	"github.com/praxzy/gatehouse/examples/employee-portal/internal/session"
)

const (
	authorizationCookieName = "employee_portal_oauth"
	sessionCookieName       = "employee_portal_session"
)

type OIDCClient interface {
	Discover(context.Context) (oidcclient.Provider, error)
	AuthorizationURL(
		oidcclient.Provider,
		oidcclient.AuthorizationFlow,
	) (string, error)
	ExchangeAndVerify(
		context.Context,
		oidcclient.Provider,
		string,
		string,
		string,
	) (oidcclient.Identity, oidcclient.TokenResponse, error)
}

type App struct {
	oidc         OIDCClient
	sessions     *session.Store
	cookieSecure bool
	templates    *template.Template
}

type pageData struct {
	Title       string
	Identity    oidcclient.Identity
	CSRFToken   string
	SignedIn    bool
	Admin       bool
	Status      int
	Message     string
	CurrentYear int
}

func New(
	oidc OIDCClient,
	sessions *session.Store,
	cookieSecure bool,
) (*App, error) {
	if oidc == nil || sessions == nil {
		return nil, errors.New(
			"invalid employee portal dependencies",
		)
	}

	parsed, err := template.New("portal").Parse(
		pageTemplates,
	)
	if err != nil {
		return nil, err
	}

	return &App{
		oidc:         oidc,
		sessions:     sessions,
		cookieSecure: cookieSecure,
		templates:    parsed,
	}, nil
}

func (app *App) Handler() http.Handler {
	router := http.NewServeMux()
	router.HandleFunc("GET /", app.home)
	router.HandleFunc("GET /login", app.login)
	router.HandleFunc("GET /oauth/callback", app.callback)
	router.HandleFunc("GET /admin", app.admin)
	router.HandleFunc("POST /logout", app.logout)

	return app.securityHeaders(router)
}

func (app *App) home(
	writer http.ResponseWriter,
	request *http.Request,
) {
	localSession, signedIn := app.currentSession(request)
	identity := localSession.Identity
	app.render(writer, http.StatusOK, "home", pageData{
		Title:     "Employee Portal",
		Identity:  identity,
		CSRFToken: localSession.CSRFToken,
		SignedIn:  signedIn,
		Admin:     hasRole(identity, "Admin"),
	})
}

func (app *App) login(
	writer http.ResponseWriter,
	request *http.Request,
) {
	provider, err := app.oidc.Discover(request.Context())
	if err != nil {
		app.renderProviderFailure(writer)
		return
	}

	flow, err := oidcclient.NewAuthorizationFlow()
	if err != nil {
		app.renderProviderFailure(writer)
		return
	}

	flowToken, err := app.sessions.BeginAuthorization(flow)
	if err != nil {
		app.renderProviderFailure(writer)
		return
	}

	target, err := app.oidc.AuthorizationURL(provider, flow)
	if err != nil {
		app.renderProviderFailure(writer)
		return
	}

	http.SetCookie(writer, app.authorizationCookie(flowToken))
	http.Redirect(
		writer,
		request,
		target,
		http.StatusFound,
	)
}

func (app *App) callback(
	writer http.ResponseWriter,
	request *http.Request,
) {
	flowCookie, err := request.Cookie(
		authorizationCookieName,
	)
	if err != nil {
		app.renderCallbackFailure(writer)
		return
	}
	app.clearAuthorizationCookie(writer)

	state, ok := singleQueryValue(request, "state")
	if !ok {
		app.renderCallbackFailure(writer)
		return
	}

	pending, ok := app.sessions.ConsumeAuthorization(
		flowCookie.Value,
		state,
	)
	if !ok {
		app.renderCallbackFailure(writer)
		return
	}

	if oauthError, present := singleOptionalQueryValue(
		request,
		"error",
	); !present {
		app.renderCallbackFailure(writer)
		return
	} else if oauthError != "" {
		app.render(
			writer,
			http.StatusForbidden,
			"error",
			pageData{
				Title:   "Access denied",
				Status:  http.StatusForbidden,
				Message: "Gatehouse did not grant access to this application.",
			},
		)
		return
	}

	code, ok := singleQueryValue(request, "code")
	if !ok {
		app.renderCallbackFailure(writer)
		return
	}

	provider, err := app.oidc.Discover(request.Context())
	if err != nil {
		app.renderProviderFailure(writer)
		return
	}

	identity, _, err := app.oidc.ExchangeAndVerify(
		request.Context(),
		provider,
		code,
		pending.CodeVerifier,
		pending.Nonce,
	)
	if err != nil {
		app.renderCallbackFailure(writer)
		return
	}

	sessionToken, _, err := app.sessions.CreateSession(identity)
	if err != nil {
		app.renderProviderFailure(writer)
		return
	}

	http.SetCookie(
		writer,
		app.sessionCookie(
			sessionToken,
			identity.ExpiresAt,
		),
	)
	http.Redirect(
		writer,
		request,
		"/",
		http.StatusSeeOther,
	)
}

func (app *App) admin(
	writer http.ResponseWriter,
	request *http.Request,
) {
	localSession, signedIn := app.currentSession(request)
	identity := localSession.Identity
	if !signedIn {
		http.Redirect(
			writer,
			request,
			"/login",
			http.StatusFound,
		)
		return
	}

	if !hasRole(identity, "Admin") {
		app.render(writer, http.StatusForbidden, "error", pageData{
			Title:     "Admin access required",
			Identity:  identity,
			CSRFToken: localSession.CSRFToken,
			SignedIn:  true,
			Status:    http.StatusForbidden,
			Message:   "Your signed Gatehouse identity does not include the Admin role.",
		})
		return
	}

	app.render(writer, http.StatusOK, "admin", pageData{
		Title:     "Admin workspace",
		Identity:  identity,
		CSRFToken: localSession.CSRFToken,
		SignedIn:  true,
		Admin:     true,
	})
}

func (app *App) logout(
	writer http.ResponseWriter,
	request *http.Request,
) {
	cookie, err := request.Cookie(sessionCookieName)
	if errors.Is(err, http.ErrNoCookie) {
		app.clearSessionCookie(writer)
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}
	if err != nil {
		http.Error(
			writer,
			http.StatusText(http.StatusForbidden),
			http.StatusForbidden,
		)
		return
	}

	localSession, ok := app.sessions.GetSession(cookie.Value)
	if !ok {
		app.clearSessionCookie(writer)
		http.Redirect(writer, request, "/", http.StatusSeeOther)
		return
	}

	if err := request.ParseForm(); err != nil ||
		len(request.PostForm["csrf_token"]) != 1 ||
		subtle.ConstantTimeCompare(
			[]byte(request.PostForm.Get("csrf_token")),
			[]byte(localSession.CSRFToken),
		) != 1 {
		http.Error(
			writer,
			http.StatusText(http.StatusForbidden),
			http.StatusForbidden,
		)
		return
	}

	app.sessions.DeleteSession(cookie.Value)
	app.clearSessionCookie(writer)
	http.Redirect(
		writer,
		request,
		"/",
		http.StatusSeeOther,
	)
}

func (app *App) currentSession(
	request *http.Request,
) (session.LocalSession, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return session.LocalSession{}, false
	}

	return app.sessions.GetSession(cookie.Value)
}

func (app *App) renderProviderFailure(
	writer http.ResponseWriter,
) {
	app.render(
		writer,
		http.StatusBadGateway,
		"error",
		pageData{
			Title:   "Sign-in unavailable",
			Status:  http.StatusBadGateway,
			Message: "The identity service is temporarily unavailable. Please try again.",
		},
	)
}

func (app *App) renderCallbackFailure(
	writer http.ResponseWriter,
) {
	app.render(
		writer,
		http.StatusBadRequest,
		"error",
		pageData{
			Title:   "Sign-in could not be completed",
			Status:  http.StatusBadRequest,
			Message: "The sign-in response was invalid or expired. Start again from this portal.",
		},
	)
}

func (app *App) render(
	writer http.ResponseWriter,
	status int,
	name string,
	data pageData,
) {
	data.CurrentYear = time.Now().UTC().Year()
	writer.Header().Set(
		"Content-Type",
		"text/html; charset=utf-8",
	)
	writer.WriteHeader(status)
	if err := app.templates.ExecuteTemplate(
		writer,
		name,
		data,
	); err != nil {
		return
	}
}

func (app *App) authorizationCookie(
	value string,
) *http.Cookie {
	return &http.Cookie{
		Name:     authorizationCookieName,
		Value:    value,
		Path:     "/oauth/callback",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   app.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (app *App) sessionCookie(
	value string,
	expiresAt time.Time,
) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   app.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (app *App) clearAuthorizationCookie(
	writer http.ResponseWriter,
) {
	cookie := app.authorizationCookie("")
	cookie.MaxAge = -1
	cookie.Expires = time.Unix(1, 0).UTC()
	http.SetCookie(writer, cookie)
}

func (app *App) clearSessionCookie(
	writer http.ResponseWriter,
) {
	cookie := app.sessionCookie("", time.Unix(1, 0).UTC())
	cookie.MaxAge = -1
	http.SetCookie(writer, cookie)
}

func (app *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set(
			"Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
		)
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func singleQueryValue(
	request *http.Request,
	key string,
) (string, bool) {
	values, exists := request.URL.Query()[key]
	return valueFromQuery(values, exists, false)
}

func singleOptionalQueryValue(
	request *http.Request,
	key string,
) (string, bool) {
	values, exists := request.URL.Query()[key]
	return valueFromQuery(values, exists, true)
}

func valueFromQuery(
	values []string,
	exists bool,
	optional bool,
) (string, bool) {
	if !exists && optional {
		return "", true
	}
	if !exists || len(values) != 1 {
		return "", false
	}
	if values[0] == "" && !optional {
		return "", false
	}

	return values[0], true
}

func hasRole(
	identity oidcclient.Identity,
	role string,
) bool {
	return slices.Contains(identity.Roles, role)
}
