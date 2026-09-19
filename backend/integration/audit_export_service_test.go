package integration_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auditexport"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type recordingAuditExportPublisher struct {
	jobIDs []pgtype.UUID
	err    error
}

func (publisher *recordingAuditExportPublisher) PublishJob(
	_ context.Context,
	jobID pgtype.UUID,
) error {
	if publisher.err != nil {
		return publisher.err
	}
	publisher.jobIDs = append(publisher.jobIDs, jobID)
	return nil
}

func TestAuditExportCreationAndDeferredDispatch(t *testing.T) {
	ctx := context.Background()
	authentication, pool := newAuthenticationTestService(t, ctx)
	queries := store.New(pool)

	owner, err := authentication.Register(ctx, auth.RegisterInput{
		TenantName:  "Audit Export Company",
		TenantSlug:  "audit-export-company",
		Email:       "owner@audit-export.test",
		DisplayName: "Audit Export Owner",
		Password:    "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("register export tenant: %v", err)
	}

	publisher := &recordingAuditExportPublisher{}
	service, err := auditexport.NewService(
		pool,
		audit.NewWriter(),
		publisher,
	)
	if err != nil {
		t.Fatalf("create audit export service: %v", err)
	}

	session := auth.SessionContext{
		TenantID:     owner.TenantID,
		MembershipID: owner.MembershipID,
		UserID:       owner.UserID,
		Permissions:  []string{auth.PermissionAuditExport},
	}

	_, err = service.Create(
		ctx,
		auth.SessionContext{
			TenantID:     owner.TenantID,
			MembershipID: owner.MembershipID,
			UserID:       owner.UserID,
		},
		auditexport.CreateInput{Format: "csv"},
	)
	if !errors.Is(err, auditexport.ErrExportForbidden) {
		t.Fatalf("expected export permission denial, got %v", err)
	}

	_, err = service.Create(
		ctx,
		session,
		auditexport.CreateInput{
			Format:    "csv",
			EventType: "unknown.event",
		},
	)
	if !errors.Is(err, auditexport.ErrInvalidExportRequest) {
		t.Fatalf("expected invalid filter rejection, got %v", err)
	}
	assertDatabaseCount(t, ctx, pool, "SELECT count(*) FROM export_jobs", 0)

	created, err := service.Create(
		ctx,
		session,
		auditexport.CreateInput{
			Format:    "csv",
			EventType: string(audit.EventLogin),
		},
	)
	if err != nil {
		t.Fatalf("create and dispatch export job: %v", err)
	}
	if !created.Enqueued || len(publisher.jobIDs) != 1 ||
		publisher.jobIDs[0] != created.Job.ID {
		t.Fatalf("expected only created job ID to be published: %+v", created)
	}

	stored, err := queries.GetTenantAuditExportJob(
		ctx,
		store.GetTenantAuditExportJobParams{
			TenantID: owner.TenantID,
			JobID:    created.Job.ID,
		},
	)
	if err != nil {
		t.Fatalf("load created export job: %v", err)
	}
	if stored.Status != "queued" || !stored.EnqueuedAt.Valid {
		t.Fatalf("created export job was not enqueued: %+v", stored)
	}
	assertDatabaseCount(
		t,
		ctx,
		pool,
		"SELECT count(*) FROM audit_events WHERE event_type = $1 AND subject_id = $2",
		1,
		string(audit.EventAuditExportRequested),
		created.Job.ID,
	)

	publisher.err = errors.New("queue unavailable")
	deferred, err := service.Create(
		ctx,
		session,
		auditexport.CreateInput{Format: "json"},
	)
	if err != nil {
		t.Fatalf("persist job during queue outage: %v", err)
	}
	if deferred.Enqueued || len(publisher.jobIDs) != 1 {
		t.Fatalf("queue outage should defer publication: %+v", deferred)
	}

	stored, err = queries.GetTenantAuditExportJob(
		ctx,
		store.GetTenantAuditExportJobParams{
			TenantID: owner.TenantID,
			JobID:    deferred.Job.ID,
		},
	)
	if err != nil {
		t.Fatalf("load deferred export job: %v", err)
	}
	if stored.Status != "queued" || stored.EnqueuedAt.Valid {
		t.Fatalf("failed queue send should leave job recoverable: %+v", stored)
	}

	publisher.err = nil
	dispatched, err := service.DispatchPending(ctx, 10)
	if err != nil || dispatched != 1 {
		t.Fatalf("dispatch deferred job: count=%d, err=%v", dispatched, err)
	}
	if len(publisher.jobIDs) != 2 ||
		publisher.jobIDs[1] != deferred.Job.ID {
		t.Fatalf("dispatcher published wrong job IDs: %+v", publisher.jobIDs)
	}
	dispatched, err = service.DispatchPending(ctx, 10)
	if err != nil || dispatched != 0 || len(publisher.jobIDs) != 2 {
		t.Fatalf("duplicate dispatch: count=%d, err=%v", dispatched, err)
	}

	auditFailure := errors.New("audit storage unavailable")
	failingService, err := auditexport.NewService(
		pool,
		failingAuditWriter{err: auditFailure},
		publisher,
	)
	if err != nil {
		t.Fatalf("create failing audit export service: %v", err)
	}
	_, err = failingService.Create(
		ctx,
		session,
		auditexport.CreateInput{Format: "csv"},
	)
	if !errors.Is(err, auditFailure) {
		t.Fatalf("expected audit failure, got %v", err)
	}
	assertDatabaseCount(t, ctx, pool, "SELECT count(*) FROM export_jobs", 2)
	if len(publisher.jobIDs) != 2 {
		t.Fatalf("rolled-back job was published: %+v", publisher.jobIDs)
	}
}
