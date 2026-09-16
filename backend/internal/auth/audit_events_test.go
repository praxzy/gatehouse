package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

func TestListAuditEventsRequiresPermission(t *testing.T) {
	service := &Service{}

	_, err := service.ListAuditEvents(
		context.Background(),
		SessionContext{},
		AuditEventFilter{},
	)
	if !errors.Is(err, ErrAuditReadForbidden) {
		t.Fatalf(
			"expected ErrAuditReadForbidden, got %v",
			err,
		)
	}
}

func TestValidateAuditFilterUsesDefaultPageSize(t *testing.T) {
	pageSize, err := validateAuditFilter(AuditEventFilter{})
	if err != nil {
		t.Fatalf("validate empty filter: %v", err)
	}

	if pageSize != defaultAuditPageSize {
		t.Fatalf(
			"expected default page size %d, got %d",
			defaultAuditPageSize,
			pageSize,
		)
	}
}

func TestValidateAuditFilterAcceptsSupportedValues(t *testing.T) {
	now := time.Now().UTC()
	eventID := pgtype.UUID{
		Bytes: [16]byte{1},
		Valid: true,
	}

	pageSize, err := validateAuditFilter(
		AuditEventFilter{
			EventType: string(audit.EventLogin),
			Outcome:   string(audit.OutcomeFailure),
			TimeFrom:  now.Add(-time.Hour),
			TimeUntil: now,
			Cursor: &AuditCursor{
				OccurredAt: now.Add(-time.Minute),
				EventID:    eventID,
			},
			PageSize: maxAuditPageSize,
		},
	)
	if err != nil {
		t.Fatalf("validate supported filter: %v", err)
	}

	if pageSize != maxAuditPageSize {
		t.Fatalf(
			"expected page size %d, got %d",
			maxAuditPageSize,
			pageSize,
		)
	}
}

func TestValidateAuditFilterRejectsInvalidValues(t *testing.T) {
	now := time.Now().UTC()
	validEventID := pgtype.UUID{
		Bytes: [16]byte{1},
		Valid: true,
	}

	tests := []struct {
		name   string
		filter AuditEventFilter
	}{
		{
			name: "negative page size",
			filter: AuditEventFilter{
				PageSize: -1,
			},
		},
		{
			name: "page size above maximum",
			filter: AuditEventFilter{
				PageSize: maxAuditPageSize + 1,
			},
		},
		{
			name: "reversed time range",
			filter: AuditEventFilter{
				TimeFrom:  now,
				TimeUntil: now.Add(-time.Hour),
			},
		},
		{
			name: "equal time range",
			filter: AuditEventFilter{
				TimeFrom:  now,
				TimeUntil: now,
			},
		},
		{
			name: "unknown event type",
			filter: AuditEventFilter{
				EventType: "unknown.event",
			},
		},
		{
			name: "unknown outcome",
			filter: AuditEventFilter{
				Outcome: "maybe",
			},
		},
		{
			name: "cursor without timestamp",
			filter: AuditEventFilter{
				Cursor: &AuditCursor{
					EventID: validEventID,
				},
			},
		},
		{
			name: "cursor without event ID",
			filter: AuditEventFilter{
				Cursor: &AuditCursor{
					OccurredAt: now,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateAuditFilter(test.filter)
			if !errors.Is(err, ErrInvalidAuditFilter) {
				t.Fatalf(
					"expected ErrInvalidAuditFilter, got %v",
					err,
				)
			}
		})
	}
}
