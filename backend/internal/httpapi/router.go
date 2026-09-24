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
	FederationManagement    FederationManagementService
	CSRF                    *CSRFProtector
	RateLimiters            RouteRateLimiters
}

type healthResponse struct {
	Status string `json:"status"`
}

func NewRouter(dependencies Dependencies) http.Handler {
	router := chi.NewRouter()
	router.Use(securityHeaders)
	router.Use(attachRequestID)
	if dependencies.CSRF != nil {
		router.Use(dependencies.CSRF.CORS)
	}

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
	federationManagementHandler := federationManagementHandler{
		management: dependencies.FederationManagement,
	}
	csrfHandler := csrfHandler{
		protector:     dependencies.CSRF,
		sessionCookie: dependencies.SessionCookie,
	}

	if dependencies.OIDCTokens != nil {
		router.With(
			optionalRequestRateLimit(
				dependencies.RateLimiters.Token,
			),
		).Post(
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
		router.With(
			optionalRequestRateLimit(
				dependencies.RateLimiters.Authorize,
			),
		).Get(
			"/oauth/authorize",
			oidcHandler.authorize,
		)

		router.With(
			optionalRequestRateLimit(
				dependencies.RateLimiters.Authorize,
			),
		).Get(
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
			if dependencies.CSRF != nil {
				router.Use(
					dependencies.CSRF.ProtectOrigin,
				)
			}
			router.Use(
				optionalRequestRateLimit(
					dependencies.RateLimiters.Invitations,
				),
			)

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

			if dependencies.CSRF != nil {
				router.Use(
					dependencies.CSRF.Protect(
						dependencies.SessionCookie,
					),
				)
			}

			router.With(
				requirePermission(auth.PermissionMemberRead),
			).Get(
				"/api/v1/members",
				handler.listMembers,
			)

			router.With(
				requirePermission(auth.PermissionMemberManage),
				optionalRequestRateLimit(
					dependencies.RateLimiters.Invitations,
				),
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
					optionalRequestRateLimit(
						dependencies.RateLimiters.SecretManagement,
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

			if dependencies.FederationManagement != nil {
				router.Route(
					"/api/v1/federation",
					func(router chi.Router) {
						router.Use(
							requirePermission(
								auth.PermissionFederationManage,
							),
						)

						router.Get(
							"/connection",
							federationManagementHandler.
								getConnection,
						)
						router.With(
							optionalRequestRateLimit(
								dependencies.RateLimiters.SecretManagement,
							),
						).Put(
							"/connection",
							federationManagementHandler.
								saveConnection,
						)
						router.Patch(
							"/connection/status",
							federationManagementHandler.
								updateConnectionStatus,
						)
						router.Get(
							"/identity-mappings",
							federationManagementHandler.
								listIdentityMappings,
						)
						router.Post(
							"/identity-mappings",
							federationManagementHandler.
								createIdentityMapping,
						)
						router.Delete(
							"/identity-mappings",
							federationManagementHandler.
								deleteIdentityMapping,
						)
					},
				)
			}
		})

		router.Route("/api/v1/auth", func(router chi.Router) {
			if dependencies.CSRF != nil {
				router.Use(
					dependencies.CSRF.ProtectOrigin,
				)
			}

			router.Post("/register", handler.register)
			router.Post("/email/verify", handler.verifyEmail)
			router.Post("/login", handler.login)

			router.Group(func(router chi.Router) {
				router.Use(requireSession(
					dependencies.Authentication,
					dependencies.SessionCookie,
				))

				if dependencies.CSRF != nil {
					router.Use(
						dependencies.CSRF.Protect(
							dependencies.SessionCookie,
						),
					)
				}

				router.Get(
					"/csrf",
					csrfHandler.token,
				)

				router.Get("/current-user", handler.currentUser)
				router.Post("/logout", handler.logout)
				router.With(
					optionalRequestRateLimit(
						dependencies.RateLimiters.MFA,
					),
				).Post(
					"/mfa/enroll",
					handler.beginTOTPEnrollment,
				)
				router.With(
					optionalRequestRateLimit(
						dependencies.RateLimiters.MFA,
					),
				).Post(
					"/mfa/enroll/confirm",
					handler.confirmTOTPEnrollment,
				)
				router.With(
					optionalRequestRateLimit(
						dependencies.RateLimiters.MFA,
					),
				).Post(
					"/mfa/challenge/totp",
					handler.completeTOTPChallenge,
				)
				router.With(
					optionalRequestRateLimit(
						dependencies.RateLimiters.MFA,
					),
				).Post(
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
