package integration_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
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
