package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type Dependencies struct {
	Authentication AuthenticationService
	SessionCookie  SessionCookie
}

type healthResponse struct {
	Status string `json:"status"`
}

func NewRouter(dependencies Dependencies) http.Handler {
	router := chi.NewRouter()
	router.Use(attachRequestID)

	router.Get("/healthz", healthz)

	if dependencies.Authentication != nil {
		handler := authHandler{
			authentication: dependencies.Authentication,
			sessionCookie:  dependencies.SessionCookie,
		}

		router.Route("/api/v1/auth", func(router chi.Router) {
			router.Post("/register", handler.register)
			router.Post("/email/verify", handler.verifyEmail)
			router.Post("/login", handler.login)

			router.Group(func(router chi.Router) {
				router.Use(requireSession(
					dependencies.Authentication,
					dependencies.SessionCookie,
				))

				router.Get("/current-user", handler.currentUser)
				router.Post("/logout", handler.logout)
				router.Post(
					"/mfa/enroll",
					handler.beginTOTPEnrollment,
				)
				router.Post(
					"/mfa/enroll/confirm",
					handler.confirmTOTPEnrollment,
				)
				router.Post(
					"/mfa/challenge/totp",
					handler.completeTOTPChallenge,
				)
				router.Post(
					"/mfa/challenge/recovery",
					handler.completeRecoveryChallenge,
				)
			})
		})
	}

	return router
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(healthResponse{
		Status: "ok",
	})
}
