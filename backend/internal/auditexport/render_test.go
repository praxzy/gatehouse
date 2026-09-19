package auditexport

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type eventPageReaderFunc func(context.Context, store.ListAuditEventsForExportParams) ([]store.AuditEvent, error)

func (read eventPageReaderFunc) ListAuditEventsForExport(
	ctx context.Context,
	params store.ListAuditEventsForExportParams,
) ([]store.AuditEvent, error) {
	return read(ctx, params)
}

func testUUID(lastByte byte) pgtype.UUID {
	var id pgtype.UUID
	id.Bytes[15] = lastByte
	id.Valid = true
	return id
}

func testExportJob(format string) store.ExportJob {
	return store.ExportJob{
		ID:         testUUID(1),
		TenantID:   testUUID(2),
		Format:     format,
		SnapshotAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), Valid: true},
	}
}

func testAuditEvent(job store.ExportJob, id byte, occurredAt time.Time) store.AuditEvent {
	return store.AuditEvent{
		ID:          testUUID(id),
		TenantID:    job.TenantID,
		ActorKind:   "user",
		ActorUserID: testUUID(10),
		EventType:   "auth.login",
		Outcome:     "success",
		Metadata:    []byte(`{"method":"password"}`),
		OccurredAt:  pgtype.Timestamptz{Time: occurredAt, Valid: true},
	}
}

func TestRendererStreamsJSONAcrossPagesUsingJobFilters(t *testing.T) {
	job := testExportJob("json")
	job.FilterActorUserID = testUUID(10)
	job.FilterEventType = new(string)
	*job.FilterEventType = "auth.login"
	job.TimeFrom = pgtype.Timestamptz{Time: job.SnapshotAt.Time.Add(-time.Hour), Valid: true}

	first := testAuditEvent(job, 3, job.SnapshotAt.Time.Add(-time.Minute))
	second := testAuditEvent(job, 4, job.SnapshotAt.Time.Add(-2*time.Minute))
	third := testAuditEvent(job, 5, job.SnapshotAt.Time.Add(-3*time.Minute))
	calls := 0
	reader := eventPageReaderFunc(func(_ context.Context, params store.ListAuditEventsForExportParams) ([]store.AuditEvent, error) {
		if params.TenantID != job.TenantID || params.SnapshotAt != job.SnapshotAt ||
			params.FilterActorUserID != job.FilterActorUserID ||
			params.FilterEventType != job.FilterEventType ||
			params.TimeFrom != job.TimeFrom || params.PageSize != 2 {
			t.Fatalf("renderer lost job binding: %+v", params)
		}
		calls++
		switch calls {
		case 1:
			if params.CursorID.Valid || params.CursorOccurredAt.Valid {
				t.Fatalf("first page has a cursor: %+v", params)
			}
			return []store.AuditEvent{first, second}, nil
		case 2:
			if params.CursorID != second.ID || params.CursorOccurredAt != second.OccurredAt {
				t.Fatalf("incorrect second-page cursor: %+v", params)
			}
			return []store.AuditEvent{third}, nil
		default:
			t.Fatal("unexpected extra page read")
			return nil, nil
		}
	})
	renderer, err := NewRenderer(reader)
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}
	renderer.pageSize = 2

	var output bytes.Buffer
	if err := renderer.Render(context.Background(), job, &output); err != nil {
		t.Fatalf("render JSON: %v", err)
	}
	var events []struct {
		ID       string         `json:"id"`
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(output.Bytes(), &events); err != nil {
		t.Fatalf("decode export JSON: %v; output=%s", err, output.String())
	}
	if calls != 2 || len(events) != 3 || events[0].ID != first.ID.String() ||
		events[1].ID != second.ID.String() || events[2].ID != third.ID.String() ||
		events[0].Metadata["method"] != "password" {
		t.Fatalf("unexpected export JSON: %+v; calls=%d", events, calls)
	}
}

func TestRendererCSVHasStableColumnsAndEscapesFormulae(t *testing.T) {
	job := testExportJob("csv")
	event := testAuditEvent(job, 3, job.SnapshotAt.Time.Add(-time.Minute))
	requestID := " =1+1"
	userAgent := "=HYPERLINK(\"https://example.test\")"
	event.RequestID = &requestID
	event.UserAgent = &userAgent
	renderer, err := NewRenderer(eventPageReaderFunc(func(_ context.Context, _ store.ListAuditEventsForExportParams) ([]store.AuditEvent, error) {
		return []store.AuditEvent{event}, nil
	}))
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}

	var output bytes.Buffer
	if err := renderer.Render(context.Background(), job, &output); err != nil {
		t.Fatalf("render CSV: %v", err)
	}
	records, err := csv.NewReader(&output).ReadAll()
	if err != nil {
		t.Fatalf("parse export CSV: %v", err)
	}
	if len(records) != 2 || !reflect.DeepEqual(records[0], csvHeader) {
		t.Fatalf("unexpected CSV records: %+v", records)
	}
	if records[1][11] != "'"+requestID || records[1][13] != "'"+userAgent ||
		records[1][14] != string(event.Metadata) {
		t.Fatalf("CSV text was not encoded safely: %+v", records[1])
	}
}

func TestRendererRejectsForeignTenantEvent(t *testing.T) {
	job := testExportJob("json")
	event := testAuditEvent(job, 3, job.SnapshotAt.Time.Add(-time.Minute))
	event.TenantID = testUUID(9)
	renderer, err := NewRenderer(eventPageReaderFunc(func(_ context.Context, _ store.ListAuditEventsForExportParams) ([]store.AuditEvent, error) {
		return []store.AuditEvent{event}, nil
	}))
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}
	var output bytes.Buffer
	if err := renderer.Render(context.Background(), job, &output); !errors.Is(err, ErrInvalidExportJob) {
		t.Fatalf("expected foreign event rejection, got %v", err)
	}
	if strings.Contains(output.String(), event.ID.String()) {
		t.Fatal("foreign event data was written")
	}
}

type failingWriter struct{ err error }

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestRendererPropagatesWriterFailure(t *testing.T) {
	job := testExportJob("csv")
	renderer, err := NewRenderer(eventPageReaderFunc(func(_ context.Context, _ store.ListAuditEventsForExportParams) ([]store.AuditEvent, error) {
		return nil, nil
	}))
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}
	writeErr := errors.New("output failed")
	if err := renderer.Render(context.Background(), job, failingWriter{err: writeErr}); !errors.Is(err, writeErr) {
		t.Fatalf("expected writer failure, got %v", err)
	}
}

func TestRendererRejectsInvalidJob(t *testing.T) {
	renderer, err := NewRenderer(eventPageReaderFunc(func(_ context.Context, _ store.ListAuditEventsForExportParams) ([]store.AuditEvent, error) {
		t.Fatal("invalid job should not read events")
		return nil, nil
	}))
	if err != nil {
		t.Fatalf("create renderer: %v", err)
	}
	job := testExportJob("json")
	job.SnapshotAt = pgtype.Timestamptz{}
	if err := renderer.Render(context.Background(), job, &bytes.Buffer{}); !errors.Is(err, ErrInvalidExportJob) {
		t.Fatalf("expected invalid job, got %v", err)
	}
}
