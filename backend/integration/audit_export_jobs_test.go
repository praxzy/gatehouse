package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

func TestAuditExportJobLifecycle(t *testing.T) {
	ctx := context.Background()
	authentication, pool := newAuthenticationTestService(t, ctx)
	queries := store.New(pool)

	owner, err := authentication.Register(ctx, auth.RegisterInput{
		TenantName:  "Export Company",
		TenantSlug:  "export-company",
		Email:       "owner@export.test",
		DisplayName: "Export Owner",
		Password:    "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("register export tenant: %v", err)
	}

	otherTenant, err := authentication.Register(ctx, auth.RegisterInput{
		TenantName:  "Other Export Company",
		TenantSlug:  "other-export-company",
		Email:       "owner@other-export.test",
		DisplayName: "Other Export Owner",
		Password:    "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("register other tenant: %v", err)
	}

	eventType := "session.created"
	outcome := "success"
	job, err := queries.CreateAuditExportJob(
		ctx,
		store.CreateAuditExportJobParams{
			TenantID:                owner.TenantID,
			RequestedByMembershipID: owner.MembershipID,
			Format:                  "csv",
			FilterActorUserID:       owner.UserID,
			FilterEventType:         &eventType,
			FilterOutcome:           &outcome,
		},
	)
	if err != nil {
		t.Fatalf("create export job: %v", err)
	}
	if !job.ID.Valid || job.Status != "queued" ||
		job.AttemptCount != 0 || !job.SnapshotAt.Valid {
		t.Fatalf("unexpected initial export job: %+v", job)
	}
	if job.TenantID != owner.TenantID ||
		job.RequestedByMembershipID != owner.MembershipID ||
		job.FilterActorUserID != owner.UserID ||
		job.FilterEventType == nil ||
		*job.FilterEventType != eventType {
		t.Fatalf("export job lost tenant or filter binding: %+v", job)
	}

	_, err = queries.GetTenantAuditExportJob(
		ctx,
		store.GetTenantAuditExportJobParams{
			TenantID: otherTenant.TenantID,
			JobID:    job.ID,
		},
	)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("foreign tenant should not see export job, got %v", err)
	}

	pending, err := queries.ListPendingAuditExportEnqueues(ctx, 10)
	if err != nil {
		t.Fatalf("list pending enqueues: %v", err)
	}
	if len(pending) != 1 || pending[0] != job.ID {
		t.Fatalf("expected new job to await enqueue, got %+v", pending)
	}

	rows, err := queries.MarkAuditExportJobEnqueued(ctx, job.ID)
	if err != nil || rows != 1 {
		t.Fatalf("mark job enqueued: rows=%d, err=%v", rows, err)
	}
	rows, err = queries.MarkAuditExportJobEnqueued(ctx, job.ID)
	if err != nil || rows != 0 {
		t.Fatalf("duplicate enqueue mark: rows=%d, err=%v", rows, err)
	}

	firstClaim, err := queries.ClaimAuditExportJob(
		ctx,
		store.ClaimAuditExportJobParams{
			JobID:        job.ID,
			LeaseSeconds: 60,
		},
	)
	if err != nil {
		t.Fatalf("claim export job: %v", err)
	}
	if firstClaim.Status != "running" ||
		firstClaim.AttemptCount != 1 ||
		!firstClaim.LeaseExpiresAt.Valid {
		t.Fatalf("unexpected first claim: %+v", firstClaim)
	}

	_, err = queries.ClaimAuditExportJob(
		ctx,
		store.ClaimAuditExportJobParams{
			JobID:        job.ID,
			LeaseSeconds: 60,
		},
	)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("active lease should block another claim, got %v", err)
	}

	_, err = pool.Exec(
		ctx,
		`UPDATE export_jobs
		 SET lease_expires_at = now() - interval '1 second'
		 WHERE id = $1`,
		job.ID,
	)
	if err != nil {
		t.Fatalf("expire export job lease: %v", err)
	}

	secondClaim, err := queries.ClaimAuditExportJob(
		ctx,
		store.ClaimAuditExportJobParams{
			JobID:        job.ID,
			LeaseSeconds: 60,
		},
	)
	if err != nil {
		t.Fatalf("reclaim expired export job: %v", err)
	}
	if secondClaim.Status != "running" ||
		secondClaim.AttemptCount != 2 {
		t.Fatalf("unexpected second claim: %+v", secondClaim)
	}

	objectKey := "audit-exports/tenant/job.csv"
	rows, err = queries.CompleteAuditExportJob(
		ctx,
		store.CompleteAuditExportJobParams{
			JobID:           job.ID,
			AttemptCount:    firstClaim.AttemptCount,
			OutputObjectKey: &objectKey,
		},
	)
	if err != nil || rows != 0 {
		t.Fatalf("stale claim completed job: rows=%d, err=%v", rows, err)
	}

	rows, err = queries.CompleteAuditExportJob(
		ctx,
		store.CompleteAuditExportJobParams{
			JobID:           job.ID,
			AttemptCount:    secondClaim.AttemptCount,
			OutputObjectKey: &objectKey,
		},
	)
	if err != nil || rows != 1 {
		t.Fatalf("complete current claim: rows=%d, err=%v", rows, err)
	}
	rows, err = queries.CompleteAuditExportJob(
		ctx,
		store.CompleteAuditExportJobParams{
			JobID:           job.ID,
			AttemptCount:    secondClaim.AttemptCount,
			OutputObjectKey: &objectKey,
		},
	)
	if err != nil || rows != 0 {
		t.Fatalf("duplicate completion: rows=%d, err=%v", rows, err)
	}

	completed, err := queries.GetTenantAuditExportJob(
		ctx,
		store.GetTenantAuditExportJobParams{
			TenantID: owner.TenantID,
			JobID:    job.ID,
		},
	)
	if err != nil {
		t.Fatalf("load completed export job: %v", err)
	}
	if completed.Status != "completed" ||
		completed.OutputObjectKey == nil ||
		*completed.OutputObjectKey != objectKey ||
		!completed.CompletedAt.Valid {
		t.Fatalf("unexpected completed export job: %+v", completed)
	}

	exhausted, err := queries.CreateAuditExportJob(ctx, store.CreateAuditExportJobParams{
		TenantID: owner.TenantID, RequestedByMembershipID: owner.MembershipID,
		Format: "json",
	})
	if err != nil {
		t.Fatalf("create exhausted job: %v", err)
	}
	_, err = pool.Exec(ctx, `UPDATE export_jobs SET status = 'running',
		attempt_count = 3, lease_expires_at = now() - interval '1 second'
		WHERE id = $1`, exhausted.ID)
	if err != nil {
		t.Fatalf("expire exhausted job lease: %v", err)
	}
	failedIDs, err := queries.FailExpiredExhaustedAuditExportJobs(ctx, 3)
	if err != nil || len(failedIDs) != 1 || failedIDs[0] != exhausted.ID {
		t.Fatalf("reconcile exhausted job: ids=%+v, err=%v", failedIDs, err)
	}
	failed, err := queries.GetTenantAuditExportJob(ctx, store.GetTenantAuditExportJobParams{
		TenantID: owner.TenantID, JobID: exhausted.ID,
	})
	if err != nil || failed.Status != "failed" || !failed.FailedAt.Valid ||
		failed.LastErrorCode == nil || *failed.LastErrorCode != "retry_exhausted" {
		t.Fatalf("exhausted job was not failed: job=%+v, err=%v", failed, err)
	}
	failedIDs, err = queries.FailExpiredExhaustedAuditExportJobs(ctx, 3)
	if err != nil || len(failedIDs) != 0 {
		t.Fatalf("reconciliation was not idempotent: ids=%+v, err=%v", failedIDs, err)
	}
}

func TestAuditExportEventPagingAndTenantIsolation(t *testing.T) {
	ctx := context.Background()
	authentication, pool := newAuthenticationTestService(t, ctx)
	queries := store.New(pool)

	register := func(name, slug, email string) auth.RegisterResult {
		t.Helper()
		result, err := authentication.Register(ctx, auth.RegisterInput{
			TenantName:  name,
			TenantSlug:  slug,
			Email:       email,
			DisplayName: "Export Owner",
			Password:    "correct horse battery staple",
		})
		if err != nil {
			t.Fatalf("register %s: %v", slug, err)
		}
		return result
	}

	owner := register("Paging Export", "paging-export", "owner@paging-export.test")
	other := register("Foreign Export", "foreign-export", "owner@foreign-export.test")

	base := time.Now().UTC().Add(-time.Hour)
	snapshot := base.Add(3 * time.Minute)

	insertEvent := func(tenantID, actorID pgtype.UUID, outcome string, occurredAt time.Time) pgtype.UUID {
		t.Helper()
		var id pgtype.UUID
		err := pool.QueryRow(ctx, `
			INSERT INTO audit_events
				(tenant_id, actor_kind, actor_user_id, event_type, outcome, occurred_at)
			VALUES ($1, 'user', $2, 'auth.login', $3, $4)
			RETURNING id
		`, tenantID, actorID, outcome, occurredAt).Scan(&id)
		if err != nil {
			t.Fatalf("insert audit event: %v", err)
		}
		return id
	}

	olderID := insertEvent(owner.TenantID, owner.UserID, "success", base.Add(time.Minute))
	newerID := insertEvent(owner.TenantID, owner.UserID, "failure", base.Add(2*time.Minute))
	insertEvent(owner.TenantID, owner.UserID, "success", base.Add(4*time.Minute))
	insertEvent(other.TenantID, other.UserID, "failure", base.Add(2*time.Minute))

	params := store.ListAuditEventsForExportParams{
		TenantID:   owner.TenantID,
		SnapshotAt: pgtype.Timestamptz{Time: snapshot, Valid: true},
		PageSize:   1,
	}
	first, err := queries.ListAuditEventsForExport(ctx, params)
	if err != nil || len(first) != 1 || first[0].ID != newerID {
		t.Fatalf("first page: events=%+v, err=%v", first, err)
	}

	params.CursorOccurredAt = first[0].OccurredAt
	params.CursorID = first[0].ID
	second, err := queries.ListAuditEventsForExport(ctx, params)
	if err != nil || len(second) != 1 || second[0].ID != olderID {
		t.Fatalf("second page: events=%+v, err=%v", second, err)
	}

	params.CursorOccurredAt = second[0].OccurredAt
	params.CursorID = second[0].ID
	third, err := queries.ListAuditEventsForExport(ctx, params)
	if err != nil || len(third) != 0 {
		t.Fatalf("expected no further events: events=%+v, err=%v", third, err)
	}

	params.CursorOccurredAt = pgtype.Timestamptz{}
	params.CursorID = pgtype.UUID{}
	params.FilterOutcome = new(string)
	*params.FilterOutcome = "failure"
	filtered, err := queries.ListAuditEventsForExport(ctx, params)
	if err != nil || len(filtered) != 1 || filtered[0].ID != newerID {
		t.Fatalf("filtered page: events=%+v, err=%v", filtered, err)
	}
}
