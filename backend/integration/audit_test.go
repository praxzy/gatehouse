package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	"github.com/praxzy/gatehouse/backend/internal/httpapi"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

func TestRegistrationAndSessionAuditLifecycle(t *testing.T) {
	t.Run(
		"audit failure rolls back registration",
		func(t *testing.T) {
			ctx := context.Background()
			auditFailure := errors.New(
				"audit storage unavailable",
			)

			service, pool :=
				newAuthenticationTestServiceWithAuditWriter(
					t,
					ctx,
					failingAuditWriter{
						err: auditFailure,
					},
				)

			_, err := service.Register(
				ctx,
				auth.RegisterInput{
					TenantName:  "Rollback Company",
					TenantSlug:  "audit-rollback-company",
					Email:       "owner@audit-rollback.test",
					DisplayName: "Rollback Owner",
					Password:    "correct horse battery staple",
				},
			)
			if !errors.Is(err, auditFailure) {
				t.Fatalf(
					"expected audit failure, got %v",
					err,
				)
			}

			tables := []string{
				"tenants",
				"users",
				"password_credentials",
				"email_verification_tokens",
				"memberships",
				"roles",
				"membership_roles",
				"role_permissions",
				"audit_events",
			}

			for _, table := range tables {
				assertDatabaseCount(
					t,
					ctx,
					pool,
					"SELECT count(*) FROM "+table,
					0,
				)
			}
		},
	)

	t.Run(
		"successful registration and login store safe events",
		func(t *testing.T) {
			ctx := context.Background()
			sourceIP := netip.MustParseAddr("192.0.2.10")
			password := "correct horse battery staple"
			emailSender := &recordingEmailVerificationSender{}

			service, pool :=
				newAuthenticationTestServiceWithEmailSender(
					t,
					ctx,
					emailSender,
				)

			registrationContext := audit.WithRequestDetails(
				ctx,
				audit.NewRequestDetails(
					"registration-request",
					&sourceIP,
					"Gatehouse integration test",
				),
			)

			registration, err := service.Register(
				registrationContext,
				auth.RegisterInput{
					TenantName:  "Audited Company",
					TenantSlug:  "audited-company",
					Email:       "owner@audited.test",
					DisplayName: "Audited Owner",
					Password:    password,
				},
			)
			if err != nil {
				t.Fatalf("register audited user: %v", err)
			}

			if len(emailSender.deliveries) != 1 {
				t.Fatalf(
					"expected one verification delivery, got %d",
					len(emailSender.deliveries),
				)
			}

			markTestEmailVerified(
				t,
				ctx,
				pool,
				registration.UserID,
			)

			loginContext := audit.WithRequestDetails(
				ctx,
				audit.NewRequestDetails(
					"login-request",
					&sourceIP,
					"Gatehouse integration test",
				),
			)

			authentication, err :=
				service.AuthenticateAndCreateSession(
					loginContext,
					auth.AuthenticateInput{
						TenantSlug: "audited-company",
						Email:      "owner@audited.test",
						Password:   password,
						ClientIP:   sourceIP.String(),
					},
				)
			if err != nil {
				t.Fatalf("authenticate audited user: %v", err)
			}

			events, err := store.New(pool).ListTenantAuditEvents(
				ctx,
				store.ListTenantAuditEventsParams{
					TenantID: registration.TenantID,
					PageSize: 20,
				},
			)
			if err != nil {
				t.Fatalf("list audit events: %v", err)
			}

			if len(events) != 3 {
				t.Fatalf(
					"expected 3 audit events, got %d",
					len(events),
				)
			}

			eventsByType := make(
				map[string]store.ListTenantAuditEventsRow,
				len(events),
			)

			for _, event := range events {
				eventsByType[event.EventType] = event

				encodedEvent := string(event.Metadata)
				for _, secret := range []string{
					password,
					emailSender.deliveries[0].Token,
					authentication.Session.Token,
				} {
					if strings.Contains(encodedEvent, secret) {
						t.Fatalf(
							"event %q contains a secret",
							event.EventType,
						)
					}
				}

				for _, forbiddenKey := range []string{
					`"password":`,
					`"password_hash":`,
					`"token":`,
					`"token_hash":`,
					`"secret":`,
					`"client_secret":`,
					`"code_verifier":`,
					`"recovery_code":`,
					`"totp_secret":`,
				} {
					if strings.Contains(
						encodedEvent,
						forbiddenKey,
					) {
						t.Fatalf(
							"event %q contains forbidden metadata key %s",
							event.EventType,
							forbiddenKey,
						)
					}
				}

				if event.SourceIp == nil ||
					*event.SourceIp != sourceIP {
					t.Fatalf(
						"event %q has unexpected source IP",
						event.EventType,
					)
				}

				if event.UserAgent == nil ||
					*event.UserAgent !=
						"Gatehouse integration test" {
					t.Fatalf(
						"event %q has unexpected user agent",
						event.EventType,
					)
				}
			}

			registrationEvent, exists :=
				eventsByType[string(audit.EventRegistration)]
			if !exists {
				t.Fatal("registration event not found")
			}

			if registrationEvent.RequestID == nil ||
				*registrationEvent.RequestID !=
					"registration-request" {
				t.Fatal(
					"registration request ID was not recorded",
				)
			}

			loginEvent, exists :=
				eventsByType[string(audit.EventLogin)]
			if !exists {
				t.Fatal("login event not found")
			}

			if loginEvent.RequestID == nil ||
				*loginEvent.RequestID != "login-request" {
				t.Fatal("login request ID was not recorded")
			}

			sessionEvent, exists :=
				eventsByType[string(audit.EventSessionCreated)]
			if !exists {
				t.Fatal("session-created event not found")
			}

			if sessionEvent.SessionID !=
				authentication.Session.SessionID {
				t.Fatal(
					"session event is not bound to created session",
				)
			}
		},
	)
}

func TestTenantAuditEventReadLifecycle(t *testing.T) {
	ctx := context.Background()
	authentication, pool := newAuthenticationTestService(t, ctx)

	owner, err := authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Audit Reader Company",
			TenantSlug:  "audit-reader-company",
			Email:       "owner@audit-reader.test",
			DisplayName: "Audit Reader",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register audit reader: %v", err)
	}

	markTestEmailVerified(t, ctx, pool, owner.UserID)

	router := httpapi.NewRouter(httpapi.Dependencies{
		Authentication: authentication,
		SessionCookie:  httpapi.NewSessionCookie(true),
	})

	ownerCookie := loginLifecycleUser(
		t,
		router,
		"audit-reader-company",
		"owner@audit-reader.test",
		"correct horse battery staple",
	)

	_, err = authentication.Register(
		ctx,
		auth.RegisterInput{
			TenantName:  "Foreign Audit Company",
			TenantSlug:  "foreign-audit-company",
			Email:       "owner@foreign-audit.test",
			DisplayName: "Foreign Owner",
			Password:    "correct horse battery staple",
		},
	)
	if err != nil {
		t.Fatalf("register foreign tenant: %v", err)
	}

	firstPage := requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?page_size=2",
		ownerCookie,
		http.StatusOK,
	)

	if len(firstPage.Events) != 2 {
		t.Fatalf(
			"expected 2 events on first page, got %d",
			len(firstPage.Events),
		)
	}
	if firstPage.NextCursor == "" {
		t.Fatal("expected next-page cursor")
	}

	secondPage := requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?"+url.Values{
			"page_size": {"2"},
			"cursor":    {firstPage.NextCursor},
		}.Encode(),
		ownerCookie,
		http.StatusOK,
	)

	if len(secondPage.Events) != 1 {
		t.Fatalf(
			"expected 1 event on second page, got %d",
			len(secondPage.Events),
		)
	}
	if secondPage.NextCursor != "" {
		t.Fatal("did not expect another cursor")
	}

	seen := make(map[string]struct{})
	for _, event := range append(
		firstPage.Events,
		secondPage.Events...,
	) {
		if _, exists := seen[event.EventID]; exists {
			t.Fatalf(
				"event %s appeared on multiple pages",
				event.EventID,
			)
		}
		seen[event.EventID] = struct{}{}

		if event.ActorEmail == "owner@foreign-audit.test" {
			t.Fatal("foreign tenant audit event was exposed")
		}
	}

	loginEvents := requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?"+url.Values{
			"event_type": {"auth.login"},
			"outcome":    {"success"},
		}.Encode(),
		ownerCookie,
		http.StatusOK,
	)

	if len(loginEvents.Events) != 1 ||
		loginEvents.Events[0].EventType != "auth.login" ||
		loginEvents.Events[0].Outcome != "success" {
		t.Fatalf(
			"unexpected filtered events: %+v",
			loginEvents.Events,
		)
	}

	actorEvents := requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?"+url.Values{
			"actor_user_id": {
				uuid.UUID(owner.UserID.Bytes).String(),
			},
		}.Encode(),
		ownerCookie,
		http.StatusOK,
	)

	if len(actorEvents.Events) != 3 {
		t.Fatalf(
			"expected 3 events for owner, got %d",
			len(actorEvents.Events),
		)
	}

	applicationEvents := requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?"+url.Values{
			"application_id": {
				"33333333-3333-4333-8333-333333333333",
			},
		}.Encode(),
		ownerCookie,
		http.StatusOK,
	)

	if len(applicationEvents.Events) != 0 {
		t.Fatal("unexpected application-filtered events")
	}

	futureEvents := requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?"+url.Values{
			"from": {
				time.Now().
					UTC().
					Add(time.Hour).
					Format(time.RFC3339),
			},
		}.Encode(),
		ownerCookie,
		http.StatusOK,
	)

	if len(futureEvents.Events) != 0 {
		t.Fatal("unexpected events beyond future time boundary")
	}

	requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events?outcome=unknown",
		ownerCookie,
		http.StatusBadRequest,
	)

	if _, err := pool.Exec(
		ctx,
		`
			DELETE FROM role_permissions AS permission
			USING roles AS role
			WHERE permission.tenant_id = role.tenant_id
			  AND permission.role_id = role.id
			  AND role.tenant_id = $1
			  AND role.role_key = 'owner'
			  AND permission.permission = 'audit.read'
		`,
		owner.TenantID,
	); err != nil {
		t.Fatalf("remove audit permission: %v", err)
	}

	requestAuditEvents(
		t,
		router,
		"/api/v1/audit-events",
		ownerCookie,
		http.StatusForbidden,
	)
}

type auditEventListTestResponse struct {
	Events []struct {
		EventID    string `json:"event_id"`
		ActorEmail string `json:"actor_email"`
		EventType  string `json:"event_type"`
		Outcome    string `json:"outcome"`
	} `json:"events"`
	NextCursor string `json:"next_cursor"`
}

func requestAuditEvents(
	t *testing.T,
	router http.Handler,
	target string,
	sessionCookie *http.Cookie,
	expectedStatus int,
) auditEventListTestResponse {
	t.Helper()

	response := performRequest(
		t,
		router,
		http.MethodGet,
		target,
		nil,
		sessionCookie,
	)

	body := requireResponseStatus(
		t,
		response,
		expectedStatus,
	)

	if expectedStatus != http.StatusOK {
		return auditEventListTestResponse{}
	}

	var result auditEventListTestResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode audit response: %v", err)
	}

	return result
}

type failingAuditWriter struct {
	err error
}

func (writer failingAuditWriter) Write(
	_ context.Context,
	_ audit.EventCreator,
	_ audit.Event,
) (store.AuditEvent, error) {
	return store.AuditEvent{}, writer.err
}
