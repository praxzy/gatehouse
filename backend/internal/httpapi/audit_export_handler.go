package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/praxzy/gatehouse/backend/internal/auditexport"
	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type AuditExportService interface {
	Create(
		context.Context,
		auth.SessionContext,
		auditexport.CreateInput,
	) (auditexport.CreateResult, error)
}

type auditExportHandler struct {
	exports AuditExportService
}

type createAuditExportRequest struct {
	Format        string `json:"format"`
	ActorUserID   string `json:"actor_user_id"`
	ApplicationID string `json:"application_id"`
	EventType     string `json:"event_type"`
	Outcome       string `json:"outcome"`
	From          string `json:"from"`
	Until         string `json:"until"`
}

type createAuditExportResponse struct {
	JobID     string `json:"job_id"`
	Status    string `json:"status"`
	Format    string `json:"format"`
	CreatedAt string `json:"created_at"`
}

func (handler auditExportHandler) create(
	writer http.ResponseWriter,
	request *http.Request,
) {
	session, ok := sessionFromContext(request.Context())
	if !ok {
		writeError(writer, http.StatusUnauthorized, "authentication required")
		return
	}
	if handler.exports == nil {
		writeError(writer, http.StatusServiceUnavailable, "audit exports unavailable")
		return
	}

	var body createAuditExportRequest
	if err := decodeJSON(writer, request, &body); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request")
		return
	}

	input := auditexport.CreateInput{
		Format:    body.Format,
		EventType: body.EventType,
		Outcome:   body.Outcome,
	}
	var err error

	if value := strings.TrimSpace(body.ActorUserID); value != "" {
		input.ActorUserID, err = parseRequestUUID(value)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid export filters")
			return
		}
	}
	if value := strings.TrimSpace(body.ApplicationID); value != "" {
		input.ApplicationID, err = parseRequestUUID(value)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid export filters")
			return
		}
	}
	if value := strings.TrimSpace(body.From); value != "" {
		input.TimeFrom, err = time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid export filters")
			return
		}
	}
	if value := strings.TrimSpace(body.Until); value != "" {
		input.TimeUntil, err = time.Parse(time.RFC3339, value)
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid export filters")
			return
		}
	}

	result, err := handler.exports.Create(request.Context(), session, input)
	if err != nil {
		switch {
		case errors.Is(err, auditexport.ErrExportForbidden):
			writeError(writer, http.StatusForbidden, "permission denied")
		case errors.Is(err, auditexport.ErrInvalidExportRequest):
			writeError(writer, http.StatusBadRequest, "invalid export request")
		default:
			writeError(writer, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	writeJSON(writer, http.StatusAccepted, createAuditExportResponse{
		JobID:     formatUUID(result.Job.ID),
		Status:    result.Job.Status,
		Format:    result.Job.Format,
		CreatedAt: result.Job.CreatedAt.Time.UTC().Format(timeFormat),
	})
}