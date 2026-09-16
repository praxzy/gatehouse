package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	defaultAuditPageSize = 50
	maxAuditPageSize     = 100
)

var (
	ErrAuditReadForbidden = errors.New("audit read forbidden")
	ErrInvalidAuditFilter = errors.New("invalid audit filter")
)

type AuditCursor struct {
	OccurredAt time.Time
	EventID    pgtype.UUID
}

type AuditEventFilter struct {
	ActorUserID   pgtype.UUID
	ApplicationID pgtype.UUID
	EventType     string
	Outcome       string
	TimeFrom      time.Time
	TimeUntil     time.Time
	Cursor        *AuditCursor
	PageSize      int
}

type AuditEventSummary struct {
	EventID           pgtype.UUID
	ActorKind         string
	ActorUserID       pgtype.UUID
	ActorMembershipID pgtype.UUID
	ActorEmail        string
	ActorDisplayName  string
	ApplicationID     pgtype.UUID
	ApplicationName   string
	SessionID         pgtype.UUID
	EventType         string
	Outcome           string
	SubjectType       string
	SubjectID         pgtype.UUID
	RequestID         string
	SourceIP          string
	UserAgent         string
	Metadata          json.RawMessage
	OccurredAt        time.Time
}

type AuditEventListResult struct {
	Events     []AuditEventSummary
	NextCursor *AuditCursor
}

func (service *Service) ListAuditEvents(
	ctx context.Context,
	session SessionContext,
	filter AuditEventFilter,
) (AuditEventListResult, error) {
	if !session.HasPermission(PermissionAuditRead) {
		return AuditEventListResult{}, ErrAuditReadForbidden
	}

	pageSize, err := validateAuditFilter(filter)
	if err != nil {
		return AuditEventListResult{}, err
	}

	params := store.ListTenantAuditEventsParams{
		TenantID:      session.TenantID,
		ActorUserID:   filter.ActorUserID,
		ApplicationID: filter.ApplicationID,
		EventType:     optionalAuditString(filter.EventType),
		Outcome:       optionalAuditString(filter.Outcome),
		TimeFrom: pgtype.Timestamptz{
			Time:  filter.TimeFrom.UTC(),
			Valid: !filter.TimeFrom.IsZero(),
		},
		TimeUntil: pgtype.Timestamptz{
			Time:  filter.TimeUntil.UTC(),
			Valid: !filter.TimeUntil.IsZero(),
		},
		PageSize: int32(pageSize + 1),
	}

	if filter.Cursor != nil {
		params.CursorOccurredAt = pgtype.Timestamptz{
			Time:  filter.Cursor.OccurredAt.UTC(),
			Valid: true,
		}
		params.CursorID = filter.Cursor.EventID
	}

	rows, err := service.queries.ListTenantAuditEvents(ctx, params)
	if err != nil {
		return AuditEventListResult{}, fmt.Errorf(
			"list tenant audit events: %w",
			err,
		)
	}

	hasMore := len(rows) > pageSize
	if hasMore {
		rows = rows[:pageSize]
	}

	events := make([]AuditEventSummary, 0, len(rows))
	for _, row := range rows {
		events = append(events, formatAuditEvent(row))
	}

	var nextCursor *AuditCursor
	if hasMore && len(events) > 0 {
		last := events[len(events)-1]
		nextCursor = &AuditCursor{
			OccurredAt: last.OccurredAt,
			EventID:    last.EventID,
		}
	}

	return AuditEventListResult{
		Events:     events,
		NextCursor: nextCursor,
	}, nil
}

func validateAuditFilter(filter AuditEventFilter) (int, error) {
	pageSize := filter.PageSize
	if pageSize == 0 {
		pageSize = defaultAuditPageSize
	}

	if pageSize < 1 || pageSize > maxAuditPageSize {
		return 0, ErrInvalidAuditFilter
	}

	if !filter.TimeFrom.IsZero() &&
		!filter.TimeUntil.IsZero() &&
		!filter.TimeUntil.After(filter.TimeFrom) {
		return 0, ErrInvalidAuditFilter
	}

	if filter.Cursor != nil &&
		(filter.Cursor.OccurredAt.IsZero() ||
			!filter.Cursor.EventID.Valid) {
		return 0, ErrInvalidAuditFilter
	}

	if filter.EventType != "" &&
		!isKnownAuditEventType(filter.EventType) {
		return 0, ErrInvalidAuditFilter
	}

	switch filter.Outcome {
	case "",
		string(audit.OutcomeSuccess),
		string(audit.OutcomeFailure),
		string(audit.OutcomeDenied):
	default:
		return 0, ErrInvalidAuditFilter
	}

	return pageSize, nil
}

func isKnownAuditEventType(candidate string) bool {
	for _, eventType := range audit.EventTypes() {
		if string(eventType) == candidate {
			return true
		}
	}

	return false
}

func optionalAuditString(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

func formatAuditEvent(
	row store.ListTenantAuditEventsRow,
) AuditEventSummary {
	event := AuditEventSummary{
		EventID:           row.ID,
		ActorKind:         row.ActorKind,
		ActorUserID:       row.ActorUserID,
		ActorMembershipID: row.ActorMembershipID,
		ApplicationID:     row.ApplicationID,
		SessionID:         row.SessionID,
		EventType:         row.EventType,
		Outcome:           row.Outcome,
		SubjectID:         row.SubjectID,
		Metadata:          json.RawMessage(row.Metadata),
		OccurredAt:        row.OccurredAt.Time,
	}

	if row.ActorEmail != nil {
		event.ActorEmail = *row.ActorEmail
	}
	if row.ActorDisplayName != nil {
		event.ActorDisplayName = *row.ActorDisplayName
	}
	if row.ApplicationName != nil {
		event.ApplicationName = *row.ApplicationName
	}
	if row.SubjectType != nil {
		event.SubjectType = *row.SubjectType
	}
	if row.RequestID != nil {
		event.RequestID = *row.RequestID
	}
	if row.SourceIp != nil {
		event.SourceIP = row.SourceIp.String()
	}
	if row.UserAgent != nil {
		event.UserAgent = *row.UserAgent
	}

	return event
}
