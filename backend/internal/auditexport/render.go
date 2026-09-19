package auditexport

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const exportPageSize int32 = 500

var ErrInvalidExportJob = errors.New("invalid audit export job")

// EventPageReader lets the renderer read bounded pages without depending on a
// particular database connection. The worker supplies a database-backed reader.
type EventPageReader interface {
	ListAuditEventsForExport(context.Context, store.ListAuditEventsForExportParams) ([]store.AuditEvent, error)
}

type Renderer struct {
	reader   EventPageReader
	pageSize int32
}

func NewRenderer(reader EventPageReader) (*Renderer, error) {
	if reader == nil {
		return nil, ErrInvalidServiceConfiguration
	}
	return &Renderer{reader: reader, pageSize: exportPageSize}, nil
}

// Render streams only events selected by the database-loaded job. It never
// accepts tenant, filters, or snapshot values from an SQS message.
func (renderer *Renderer) Render(
	ctx context.Context,
	job store.ExportJob,
	output io.Writer,
) error {
	if renderer == nil || renderer.reader == nil || output == nil {
		return ErrInvalidServiceConfiguration
	}
	if !job.ID.Valid || !job.TenantID.Valid || !job.SnapshotAt.Valid ||
		(job.Format != "csv" && job.Format != "json") || renderer.pageSize < 1 {
		return ErrInvalidExportJob
	}

	params := store.ListAuditEventsForExportParams{
		TenantID:            job.TenantID,
		SnapshotAt:          job.SnapshotAt,
		FilterActorUserID:   job.FilterActorUserID,
		FilterApplicationID: job.FilterApplicationID,
		FilterEventType:     job.FilterEventType,
		FilterOutcome:       job.FilterOutcome,
		TimeFrom:            job.TimeFrom,
		TimeUntil:           job.TimeUntil,
		PageSize:            renderer.pageSize,
	}

	var csvOutput *csv.Writer
	var jsonOutput *json.Encoder
	if job.Format == "csv" {
		csvOutput = csv.NewWriter(output)
		if err := csvOutput.Write(csvHeader); err != nil {
			return fmt.Errorf("write audit export header: %w", err)
		}
	} else {
		if _, err := io.WriteString(output, "["); err != nil {
			return fmt.Errorf("start audit export JSON: %w", err)
		}
		jsonOutput = json.NewEncoder(output)
	}

	written := 0
	for {
		page, err := renderer.reader.ListAuditEventsForExport(ctx, params)
		if err != nil {
			return fmt.Errorf("read audit export events: %w", err)
		}
		if len(page) > int(params.PageSize) {
			return ErrInvalidExportJob
		}

		for _, event := range page {
			if event.TenantID != job.TenantID || !event.ID.Valid ||
				!event.OccurredAt.Valid ||
				!event.OccurredAt.Time.Before(job.SnapshotAt.Time) {
				return ErrInvalidExportJob
			}
			if csvOutput != nil {
				if err := csvOutput.Write(csvEvent(event)); err != nil {
					return fmt.Errorf("write audit export CSV event: %w", err)
				}
			} else {
				if written > 0 {
					if _, err := io.WriteString(output, ","); err != nil {
						return fmt.Errorf("separate audit export JSON events: %w", err)
					}
				}
				// AuditEvent.Metadata is []byte, which encoding/json would
				// otherwise render as base64 rather than the stored JSON object.
				value := struct {
					store.AuditEvent
					Metadata json.RawMessage `json:"metadata"`
				}{AuditEvent: event, Metadata: json.RawMessage(event.Metadata)}
				if err := jsonOutput.Encode(value); err != nil {
					return fmt.Errorf("write audit export JSON event: %w", err)
				}
			}
			written++
		}

		if len(page) < int(params.PageSize) {
			break
		}
		last := page[len(page)-1]
		params.CursorOccurredAt = last.OccurredAt
		params.CursorID = last.ID
	}

	if csvOutput != nil {
		csvOutput.Flush()
		if err := csvOutput.Error(); err != nil {
			return fmt.Errorf("flush audit export CSV: %w", err)
		}
		return nil
	}
	if _, err := io.WriteString(output, "]\n"); err != nil {
		return fmt.Errorf("finish audit export JSON: %w", err)
	}
	return nil
}

var csvHeader = []string{
	"id", "tenant_id", "actor_kind", "actor_user_id",
	"actor_membership_id", "application_id", "session_id",
	"event_type", "outcome", "subject_type", "subject_id",
	"request_id", "source_ip", "user_agent", "metadata", "occurred_at",
}

func csvEvent(event store.AuditEvent) []string {
	sourceIP := ""
	if event.SourceIp != nil {
		sourceIP = event.SourceIp.String()
	}
	return []string{
		event.ID.String(),
		event.TenantID.String(),
		csvSafe(event.ActorKind),
		event.ActorUserID.String(),
		event.ActorMembershipID.String(),
		event.ApplicationID.String(),
		event.SessionID.String(),
		csvSafe(event.EventType),
		csvSafe(event.Outcome),
		csvSafe(optionalText(event.SubjectType)),
		event.SubjectID.String(),
		csvSafe(optionalText(event.RequestID)),
		sourceIP,
		csvSafe(optionalText(event.UserAgent)),
		csvSafe(string(event.Metadata)),
		event.OccurredAt.Time.UTC().Format(time.RFC3339Nano),
	}
}

func optionalText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// Spreadsheet applications may interpret cells beginning with these characters
// as formulas, even after leading whitespace. Prefixing an apostrophe keeps
// user-controlled audit fields as text.
func csvSafe(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}

var _ EventPageReader = (*store.Queries)(nil)
