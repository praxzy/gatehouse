package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type auditCursorPayload struct {
	OccurredAt string `json:"occurred_at"`
	EventID    string `json:"event_id"`
}

type auditEventResponse struct {
	EventID           string          `json:"event_id"`
	ActorKind         string          `json:"actor_kind"`
	ActorUserID       string          `json:"actor_user_id,omitempty"`
	ActorMembershipID string          `json:"actor_membership_id,omitempty"`
	ActorEmail        string          `json:"actor_email,omitempty"`
	ActorDisplayName  string          `json:"actor_display_name,omitempty"`
	ApplicationID     string          `json:"application_id,omitempty"`
	ApplicationName   string          `json:"application_name,omitempty"`
	SessionID         string          `json:"session_id,omitempty"`
	EventType         string          `json:"event_type"`
	Outcome           string          `json:"outcome"`
	SubjectType       string          `json:"subject_type,omitempty"`
	SubjectID         string          `json:"subject_id,omitempty"`
	RequestID         string          `json:"request_id,omitempty"`
	SourceIP          string          `json:"source_ip,omitempty"`
	UserAgent         string          `json:"user_agent,omitempty"`
	Metadata          json.RawMessage `json:"metadata"`
	OccurredAt        string          `json:"occurred_at"`
}

type auditEventListResponse struct {
	Events     []auditEventResponse `json:"events"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

func (handler authHandler) listAuditEvents(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(
			writer,
			http.StatusUnauthorized,
			"authentication required",
		)
		return
	}

	filter, err := parseAuditEventFilter(request.URL.Query())
	if err != nil {
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid audit filters",
		)
		return
	}

	result, err := handler.authentication.ListAuditEvents(
		request.Context(),
		session,
		filter,
	)
	if err != nil {
		writeAuditReadError(writer, err)
		return
	}

	response := auditEventListResponse{
		Events: make(
			[]auditEventResponse,
			0,
			len(result.Events),
		),
	}

	for _, event := range result.Events {
		response.Events = append(
			response.Events,
			formatAuditEventResponse(event),
		)
	}

	if result.NextCursor != nil {
		response.NextCursor, err = encodeAuditCursor(
			*result.NextCursor,
		)
		if err != nil {
			writeError(
				writer,
				http.StatusInternalServerError,
				"internal server error",
			)
			return
		}
	}

	writeJSON(writer, http.StatusOK, response)
}

func parseAuditEventFilter(
	values url.Values,
) (auth.AuditEventFilter, error) {
	filter := auth.AuditEventFilter{
		EventType: strings.TrimSpace(values.Get("event_type")),
		Outcome:   strings.TrimSpace(values.Get("outcome")),
	}

	var err error

	if value := strings.TrimSpace(
		values.Get("actor_user_id"),
	); value != "" {
		filter.ActorUserID, err = parseRequestUUID(value)
		if err != nil {
			return auth.AuditEventFilter{}, err
		}
	}

	if value := strings.TrimSpace(
		values.Get("application_id"),
	); value != "" {
		filter.ApplicationID, err = parseRequestUUID(value)
		if err != nil {
			return auth.AuditEventFilter{}, err
		}
	}

	if value := strings.TrimSpace(values.Get("from")); value != "" {
		filter.TimeFrom, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return auth.AuditEventFilter{}, err
		}
	}

	if value := strings.TrimSpace(values.Get("until")); value != "" {
		filter.TimeUntil, err = time.Parse(time.RFC3339, value)
		if err != nil {
			return auth.AuditEventFilter{}, err
		}
	}

	if value := strings.TrimSpace(
		values.Get("page_size"),
	); value != "" {
		filter.PageSize, err = strconv.Atoi(value)
		if err != nil {
			return auth.AuditEventFilter{}, err
		}
	}

	if value := strings.TrimSpace(values.Get("cursor")); value != "" {
		filter.Cursor, err = decodeAuditCursor(value)
		if err != nil {
			return auth.AuditEventFilter{}, err
		}
	}

	return filter, nil
}

func encodeAuditCursor(cursor auth.AuditCursor) (string, error) {
	payload, err := json.Marshal(auditCursorPayload{
		OccurredAt: cursor.OccurredAt.UTC().Format(
			time.RFC3339Nano,
		),
		EventID: formatUUID(cursor.EventID),
	})
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeAuditCursor(value string) (*auth.AuditCursor, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	var payload auditCursorPayload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return nil, err
	}

	occurredAt, err := time.Parse(
		time.RFC3339Nano,
		payload.OccurredAt,
	)
	if err != nil {
		return nil, err
	}

	eventID, err := parseRequestUUID(payload.EventID)
	if err != nil {
		return nil, err
	}

	return &auth.AuditCursor{
		OccurredAt: occurredAt,
		EventID:    eventID,
	}, nil
}

func formatAuditEventResponse(
	event auth.AuditEventSummary,
) auditEventResponse {
	return auditEventResponse{
		EventID:           formatUUID(event.EventID),
		ActorKind:         event.ActorKind,
		ActorUserID:       formatUUID(event.ActorUserID),
		ActorMembershipID: formatUUID(event.ActorMembershipID),
		ActorEmail:        event.ActorEmail,
		ActorDisplayName:  event.ActorDisplayName,
		ApplicationID:     formatUUID(event.ApplicationID),
		ApplicationName:   event.ApplicationName,
		SessionID:         formatUUID(event.SessionID),
		EventType:         event.EventType,
		Outcome:           event.Outcome,
		SubjectType:       event.SubjectType,
		SubjectID:         formatUUID(event.SubjectID),
		RequestID:         event.RequestID,
		SourceIP:          event.SourceIP,
		UserAgent:         event.UserAgent,
		Metadata:          event.Metadata,
		OccurredAt: event.OccurredAt.UTC().Format(
			time.RFC3339Nano,
		),
	}
}

func writeAuditReadError(
	writer http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(err, auth.ErrAuditReadForbidden):
		writeError(
			writer,
			http.StatusForbidden,
			"permission denied",
		)
	case errors.Is(err, auth.ErrInvalidAuditFilter):
		writeError(
			writer,
			http.StatusBadRequest,
			"invalid audit filters",
		)
	default:
		writeError(
			writer,
			http.StatusInternalServerError,
			"internal server error",
		)
	}
}
