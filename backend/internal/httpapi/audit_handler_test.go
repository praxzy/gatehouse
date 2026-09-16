package httpapi

import (
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

func TestAuditCursorRoundTripPreservesOrderingValues(
	t *testing.T,
) {
	occurredAt := time.Date(
		2026,
		time.September,
		5,
		12,
		30,
		45,
		123456789,
		time.UTC,
	)
	eventID := pgtype.UUID{
		Bytes: [16]byte{
			0x11, 0x11, 0x11, 0x11,
			0x11, 0x11,
			0x41, 0x11,
			0x81, 0x11,
			0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		},
		Valid: true,
	}

	encoded, err := encodeAuditCursor(auth.AuditCursor{
		OccurredAt: occurredAt,
		EventID:    eventID,
	})
	if err != nil {
		t.Fatalf("encode audit cursor: %v", err)
	}

	decoded, err := decodeAuditCursor(encoded)
	if err != nil {
		t.Fatalf("decode audit cursor: %v", err)
	}

	if !decoded.OccurredAt.Equal(occurredAt) {
		t.Fatalf(
			"expected timestamp %s, got %s",
			occurredAt,
			decoded.OccurredAt,
		)
	}

	if decoded.EventID != eventID {
		t.Fatalf(
			"expected event ID %v, got %v",
			eventID,
			decoded.EventID,
		)
	}
}

func TestParseAuditEventFilter(t *testing.T) {
	cursorTime := time.Date(
		2026,
		time.September,
		5,
		12,
		30,
		45,
		987654321,
		time.UTC,
	)
	cursor, err := encodeAuditCursor(auth.AuditCursor{
		OccurredAt: cursorTime,
		EventID: pgtype.UUID{
			Bytes: [16]byte{3},
			Valid: true,
		},
	})
	if err != nil {
		t.Fatalf("encode cursor fixture: %v", err)
	}

	values := url.Values{
		"actor_user_id": {
			"11111111-1111-4111-8111-111111111111",
		},
		"application_id": {
			"22222222-2222-4222-8222-222222222222",
		},
		"event_type": {"auth.login"},
		"outcome":    {"failure"},
		"from":       {"2026-09-01T00:00:00Z"},
		"until":      {"2026-09-06T00:00:00Z"},
		"page_size":  {"25"},
		"cursor":     {cursor},
	}

	filter, err := parseAuditEventFilter(values)
	if err != nil {
		t.Fatalf("parse audit filter: %v", err)
	}

	if !filter.ActorUserID.Valid {
		t.Fatal("expected actor user filter")
	}
	if !filter.ApplicationID.Valid {
		t.Fatal("expected application filter")
	}
	if filter.EventType != "auth.login" {
		t.Fatalf("unexpected event type %q", filter.EventType)
	}
	if filter.Outcome != "failure" {
		t.Fatalf("unexpected outcome %q", filter.Outcome)
	}
	if filter.PageSize != 25 {
		t.Fatalf("expected page size 25, got %d", filter.PageSize)
	}
	if filter.TimeFrom.IsZero() || filter.TimeUntil.IsZero() {
		t.Fatal("expected time range filters")
	}
	if filter.Cursor == nil {
		t.Fatal("expected decoded cursor")
	}
	if !filter.Cursor.OccurredAt.Equal(cursorTime) {
		t.Fatalf(
			"unexpected cursor timestamp %s",
			filter.Cursor.OccurredAt,
		)
	}
}

func TestParseAuditEventFilterRejectsMalformedValues(
	t *testing.T,
) {
	tests := []struct {
		name   string
		values url.Values
	}{
		{
			name: "actor user ID",
			values: url.Values{
				"actor_user_id": {"not-a-uuid"},
			},
		},
		{
			name: "application ID",
			values: url.Values{
				"application_id": {"not-a-uuid"},
			},
		},
		{
			name: "from timestamp",
			values: url.Values{
				"from": {"yesterday"},
			},
		},
		{
			name: "until timestamp",
			values: url.Values{
				"until": {"tomorrow"},
			},
		},
		{
			name: "page size",
			values: url.Values{
				"page_size": {"many"},
			},
		},
		{
			name: "cursor",
			values: url.Values{
				"cursor": {"not-base64"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseAuditEventFilter(
				test.values,
			); err == nil {
				t.Fatal("expected malformed filter to fail")
			}
		})
	}
}
