package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type Dependencies struct {
	Authentication          AuthenticationService
	Applications            ApplicationService
	AuditExports            AuditExportService
	OIDCMetadata            OIDCMetadataService
	SessionCookie           SessionCookie
	OIDCAuthorization       OIDCAuthorizationService
	OIDCTokens              OIDCTokenService
	FederationAuthorization FederationAuthorizationStarter
	FederationCallback      FederationAuthorizationCompleter
}

type healthResponse struct {
	Status string `json:"status"`
}

func NewRouter(dependencies Dependencies) http.Handler {
	router := chi.NewRouter()
	router.Use(attachRequestID)

	router.Get("/healthz", healthz)

	oidcHandler := oidcHandler{
		metadata:       dependencies.OIDCMetadata,
		authorization:  dependencies.OIDCAuthorization,
		authentication: dependencies.Authentication,
		sessionCookie:  dependencies.SessionCookie,
	}
	tokenHandler := oidcTokenHandler{
		tokens: dependencies.OIDCTokens,
	}
	federationHandler := federationHandler{
		authorization: dependencies.FederationAuthorization,
		callback:      dependencies.FederationCallback,
		sessionCookie: dependencies.SessionCookie,
	}

	if dependencies.OIDCTokens != nil {
		router.Post(
			"/oauth/token",
			tokenHandler.exchange,
		)
	}

	if dependencies.OIDCMetadata != nil {

		router.Get(
			"/.well-known/openid-configuration",
			oidcHandler.discovery,
		)
		router.Get(
			"/.well-known/jwks.json",
			oidcHandler.jwks,
		)
	}

	if dependencies.OIDCAuthorization != nil {
		router.Get(
			"/oauth/authorize",
			oidcHandler.authorize,
		)

		router.Get(
			"/oauth/authorize/continue",
			oidcHandler.continueAuthorization,
		)
	}

	if dependencies.FederationAuthorization != nil {
		router.Get(
			"/api/v1/auth/federation/{tenantSlug}/start",
			federationHandler.begin,
		)
	}

	if dependencies.FederationCallback != nil {
		router.Get(
			"/api/v1/auth/federation/callback",
			federationHandler.complete,
		)
	}

	if dependencies.Authentication != nil {
		handler := authHandler{
			authentication: dependencies.Authentication,
			sessionCookie:  dependencies.SessionCookie,
		}
		applicationHandler := applicationHandler{
			applications: dependencies.Applications,
		}
		exportHandler := auditExportHandler{
			exports: dependencies.AuditExports,
		}

		router.Route("/api/v1/invitations", func(router chi.Router) {
			router.Post(
				"/preview",
				handler.previewMembershipInvitation,
			)
			router.Post(
				"/accept",
				handler.acceptMembershipInvitation,
			)
		})

		router.Group(func(router chi.Router) {
			router.Use(requireSession(
				dependencies.Authentication,
				dependencies.SessionCookie,
			))
			router.Use(requireFullyAuthenticated)

			router.With(
				requirePermission(auth.PermissionMemberRead),
			).Get(
				"/api/v1/members",
				handler.listMembers,
			)

			router.With(
				requirePermission(auth.PermissionMemberManage),
			).Post(
				"/api/v1/members",
				handler.inviteMember,
			)

			router.With(
				requirePermission(auth.PermissionMemberManage),
			).Patch(
				"/api/v1/members/{membershipID}",
				handler.updateMember,
			)

			router.With(
				requirePermission(auth.PermissionRoleRead),
			).Get(
				"/api/v1/roles",
				handler.listRoles,
			)

			router.With(
				requirePermission(auth.PermissionRoleManage),
			).Post(
				"/api/v1/roles",
				handler.createRole,
			)

			router.With(
				requirePermission(auth.PermissionRoleManage),
			).Put(
				"/api/v1/roles/{roleID}",
				handler.updateRole,
			)

			router.With(
				requirePermission(auth.PermissionAuditRead),
			).Get(
				"/api/v1/audit-events",
				handler.listAuditEvents,
			)

			router.With(
				requirePermission(auth.PermissionAuditExport),
			).Post(
				"/api/v1/audit-exports",
				exportHandler.create,
			)

			if dependencies.Applications != nil {
				router.With(
					requirePermission(
						auth.PermissionApplicationRead,
					),
				).Get(
					"/api/v1/applications",
					applicationHandler.listApplications,
				)

				router.With(
					requirePermission(
						auth.PermissionApplicationManage,
					),
				).Post(
					"/api/v1/applications",
					applicationHandler.createApplication,
				)

				router.With(
					requirePermission(
						auth.PermissionApplicationRead,
					),
				).Get(
					"/api/v1/applications/{applicationID}",
					applicationHandler.getApplication,
				)

				router.With(
					requirePermission(
						auth.PermissionApplicationManage,
					),
				).Patch(
					"/api/v1/applications/{applicationID}/access-policy",
					applicationHandler.updateApplicationAccessPolicy,
				)
			}
		})

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
