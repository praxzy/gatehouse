package audit_test

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

func TestValidEvent(t *testing.T) {
	t.Parallel()

	event := audit.Event{
		TenantID:          testUUID(1),
		ActorKind:         audit.ActorUser,
		ActorUserID:       testUUID(2),
		ActorMembershipID: testUUID(3),
		Type:              audit.EventLogin,
		Outcome:           audit.OutcomeSuccess,
		SubjectType:       "session",
		SubjectID:         testUUID(4),
		RequestID:         "request-123",
		UserAgent:         "Gatehouse test client",
		Metadata: audit.Metadata{
			"authentication_method": "password",
		},
	}

	if err := audit.Validate(event); err != nil {
		t.Fatalf("expected valid audit event, got %v", err)
	}
}

func TestUnknownEventTypeIsRejected(t *testing.T) {
	t.Parallel()

	event := baseEvent(audit.EventType("unknown.event"))

	err := audit.Validate(event)
	if !errors.Is(err, audit.ErrUnknownEventType) {
		t.Fatalf("expected ErrUnknownEventType, got %v", err)
	}
}

func TestSensitiveMetadataKeysAreRejectedForEveryEvent(
	t *testing.T,
) {
	t.Parallel()

	sensitiveKeys := []string{
		"password",
		"password_hash",
		"token",
		"token_hash",
		"session_token",
		"client_secret",
		"client_secret_hash",
		"totp_secret",
		"recovery_code",
		"authorization_code",
		"code_verifier",
		"code_challenge",
		"email_verification_token",
		"invitation_token",
	}

	for _, eventType := range audit.EventTypes() {
		for _, sensitiveKey := range sensitiveKeys {
			eventType := eventType
			sensitiveKey := sensitiveKey

			t.Run(
				string(eventType)+"/"+sensitiveKey,
				func(t *testing.T) {
					t.Parallel()

					event := baseEvent(eventType)
					event.Metadata = audit.Metadata{
						sensitiveKey: "must-not-be-recorded",
					}

					err := audit.Validate(event)
					if !errors.Is(
						err,
						audit.ErrMetadataKeyForbidden,
					) {
						t.Fatalf(
							"expected forbidden key %q for %s, got %v",
							sensitiveKey,
							eventType,
							err,
						)
					}
				},
			)
		}
	}
}

func TestUnexpectedMetadataKeyIsRejected(t *testing.T) {
	t.Parallel()

	event := baseEvent(audit.EventApplicationCreated)
	event.Metadata = audit.Metadata{
		"unexpected": "value",
	}

	err := audit.Validate(event)
	if !errors.Is(err, audit.ErrMetadataKeyForbidden) {
		t.Fatalf("expected ErrMetadataKeyForbidden, got %v", err)
	}
}

func TestNestedMetadataIsRejected(t *testing.T) {
	t.Parallel()

	event := baseEvent(audit.EventLogin)
	event.Metadata = audit.Metadata{
		"failure_reason": map[string]any{
			"raw_request": "unsafe",
		},
	}

	err := audit.Validate(event)
	if !errors.Is(err, audit.ErrInvalidMetadataValue) {
		t.Fatalf("expected ErrInvalidMetadataValue, got %v", err)
	}
}

func TestInvalidActorCombinationsAreRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*audit.Event)
	}{
		{
			name: "user without user ID",
			mutate: func(event *audit.Event) {
				event.ActorKind = audit.ActorUser
			},
		},
		{
			name: "user without tenant",
			mutate: func(event *audit.Event) {
				event.ActorKind = audit.ActorUser
				event.ActorUserID = testUUID(2)
				event.TenantID = pgtype.UUID{}
			},
		},
		{
			name: "application without application ID",
			mutate: func(event *audit.Event) {
				event.ActorKind = audit.ActorApplication
			},
		},
		{
			name: "anonymous with user ID",
			mutate: func(event *audit.Event) {
				event.ActorKind = audit.ActorAnonymous
				event.ActorUserID = testUUID(2)
			},
		},
		{
			name: "membership without user",
			mutate: func(event *audit.Event) {
				event.ActorMembershipID = testUUID(3)
			},
		},
		{
			name: "unknown actor",
			mutate: func(event *audit.Event) {
				event.ActorKind = audit.ActorKind("unknown")
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			event := baseEvent(audit.EventLogin)
			test.mutate(&event)

			err := audit.Validate(event)
			if !errors.Is(err, audit.ErrInvalidEvent) {
				t.Fatalf("expected ErrInvalidEvent, got %v", err)
			}
		})
	}
}

func TestInvalidOutcomeIsRejected(t *testing.T) {
	t.Parallel()

	event := baseEvent(audit.EventLogin)
	event.Outcome = audit.Outcome("unknown")

	err := audit.Validate(event)
	if !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent, got %v", err)
	}
}

func TestIncompleteSubjectIsRejected(t *testing.T) {
	t.Parallel()

	event := baseEvent(audit.EventMemberStatusChanged)
	event.SubjectType = "membership"

	err := audit.Validate(event)
	if !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent, got %v", err)
	}

	event = baseEvent(audit.EventMemberStatusChanged)
	event.SubjectID = testUUID(4)

	err = audit.Validate(event)
	if !errors.Is(err, audit.ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent, got %v", err)
	}
}

func TestOversizedContextFieldsAreRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*audit.Event)
	}{
		{
			name: "request ID",
			mutate: func(event *audit.Event) {
				event.RequestID = strings.Repeat("r", 101)
			},
		},
		{
			name: "user agent",
			mutate: func(event *audit.Event) {
				event.UserAgent = strings.Repeat("u", 513)
			},
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			event := baseEvent(audit.EventLogin)
			test.mutate(&event)

			err := audit.Validate(event)
			if !errors.Is(err, audit.ErrInvalidEvent) {
				t.Fatalf("expected ErrInvalidEvent, got %v", err)
			}
		})
	}
}

func TestEventTypesAreSortedAndUnique(t *testing.T) {
	t.Parallel()

	eventTypes := audit.EventTypes()

	if !sort.SliceIsSorted(
		eventTypes,
		func(left, right int) bool {
			return eventTypes[left] < eventTypes[right]
		},
	) {
		t.Fatal("expected event types to be sorted")
	}

	seen := make(map[audit.EventType]struct{}, len(eventTypes))
	for _, eventType := range eventTypes {
		if _, exists := seen[eventType]; exists {
			t.Fatalf("duplicate event type %q", eventType)
		}

		seen[eventType] = struct{}{}
	}
}

func baseEvent(eventType audit.EventType) audit.Event {
	return audit.Event{
		TenantID:  testUUID(1),
		ActorKind: audit.ActorSystem,
		Type:      eventType,
		Outcome:   audit.OutcomeSuccess,
	}
}

func testUUID(lastByte byte) pgtype.UUID {
	var value [16]byte
	value[15] = lastByte

	return pgtype.UUID{
		Bytes: value,
		Valid: true,
	}
}
