package auditexport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var (
	ErrInvalidProcessorConfiguration = errors.New("invalid audit export processor configuration")
	ErrInvalidExportJobID            = errors.New("invalid audit export job ID")
	ErrInvalidClaimedExportJob       = errors.New("invalid claimed audit export job")
	ErrExportClaimLost               = errors.New("audit export claim lost")
	ErrEmptyExportObjectKey          = errors.New("empty audit export object key")
)

const MaxExportAttempts int32 = 3

// JobClaimer deliberately accepts only a job ID. The claim returns the
// database-owned tenant, filters, and snapshot that the worker must use.
type JobClaimer interface {
	ClaimAuditExportJob(context.Context, store.ClaimAuditExportJobParams) (store.ExportJob, error)
	GetAuditExportJobByID(context.Context, pgtype.UUID) (store.ExportJob, error)
}

type JobProcessorStore interface {
	JobClaimer
	RenewAuditExportJobLease(context.Context, store.RenewAuditExportJobLeaseParams) (int64, error)
	CompleteAuditExportJob(context.Context, store.CompleteAuditExportJobParams) (int64, error)
	FailAuditExportJob(context.Context, store.FailAuditExportJobParams) (int64, error)
	FailExpiredExhaustedAuditExportJobs(context.Context, int32) ([]pgtype.UUID, error)
}

type EventRenderer interface {
	Render(context.Context, store.ExportJob, io.Writer) error
}

type ClaimDisposition string

const (
	ClaimReady     ClaimDisposition = "ready"
	ClaimCompleted ClaimDisposition = "completed"
	ClaimBusy      ClaimDisposition = "busy"
	ClaimFailed    ClaimDisposition = "failed"
	ClaimUnknown   ClaimDisposition = "unknown"
)

type ClaimResult struct {
	Disposition ClaimDisposition
	Job         store.ExportJob
}

type Processor struct {
	jobs          JobProcessorStore
	renderer      EventRenderer
	objects       ObjectStore
	leaseSeconds  int32
	renewInterval time.Duration
}

func NewProcessor(
	jobs JobProcessorStore,
	renderer EventRenderer,
	objects ObjectStore,
	leaseSeconds int32,
) (*Processor, error) {
	if jobs == nil || renderer == nil || objects == nil || leaseSeconds < 1 {
		return nil, ErrInvalidProcessorConfiguration
	}
	return &Processor{
		jobs:          jobs,
		renderer:      renderer,
		objects:       objects,
		leaseSeconds:  leaseSeconds,
		renewInterval: time.Duration(leaseSeconds) * time.Second / 3,
	}, nil
}

// Claim resolves the result of an atomic claim. A no-row result does not by
// itself tell us whether another worker is running, the job has finished, or
// the message refers to a nonexistent job, so it is followed by a DB lookup.
func (processor *Processor) Claim(ctx context.Context, jobID pgtype.UUID) (ClaimResult, error) {
	if processor == nil || processor.jobs == nil || processor.renderer == nil ||
		processor.objects == nil || processor.leaseSeconds < 1 {
		return ClaimResult{}, ErrInvalidProcessorConfiguration
	}
	if !jobID.Valid {
		return ClaimResult{}, ErrInvalidExportJobID
	}

	job, err := processor.jobs.ClaimAuditExportJob(ctx, store.ClaimAuditExportJobParams{
		JobID:        jobID,
		LeaseSeconds: processor.leaseSeconds,
	})
	if err == nil {
		if job.ID != jobID || !job.TenantID.Valid || !job.SnapshotAt.Valid ||
			job.Status != "running" || job.AttemptCount < 1 || !job.LeaseExpiresAt.Valid {
			return ClaimResult{}, ErrInvalidClaimedExportJob
		}
		if job.AttemptCount > MaxExportAttempts {
			rows, failErr := processor.jobs.FailAuditExportJob(ctx, store.FailAuditExportJobParams{
				JobID: job.ID, AttemptCount: job.AttemptCount,
				LastErrorCode: stringPointer("retry_exhausted"),
			})
			if failErr != nil {
				return ClaimResult{}, fmt.Errorf("fail exhausted audit export job: %w", failErr)
			}
			if rows != 1 {
				return ClaimResult{}, ErrExportClaimLost
			}
			return ClaimResult{Disposition: ClaimFailed, Job: job}, nil
		}
		return ClaimResult{Disposition: ClaimReady, Job: job}, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ClaimResult{}, fmt.Errorf("claim audit export job: %w", err)
	}

	job, err = processor.jobs.GetAuditExportJobByID(ctx, jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ClaimResult{Disposition: ClaimUnknown}, nil
	}
	if err != nil {
		return ClaimResult{}, fmt.Errorf("inspect unclaimed audit export job: %w", err)
	}
	if job.ID != jobID {
		return ClaimResult{}, ErrInvalidClaimedExportJob
	}

	switch job.Status {
	case "completed":
		return ClaimResult{Disposition: ClaimCompleted, Job: job}, nil
	case "running", "queued":
		// A running job may still hold a lease. A queued job can race with a
		// state change; neither should be acknowledged as completed.
		return ClaimResult{Disposition: ClaimBusy, Job: job}, nil
	case "failed":
		return ClaimResult{Disposition: ClaimFailed, Job: job}, nil
	default:
		return ClaimResult{}, ErrInvalidClaimedExportJob
	}
}

// Process streams the claimed job into object storage. A duplicate completed
// delivery is idempotent; busy and unknown jobs are returned for the SQS
// consumer to handle without exporting anything.
func (processor *Processor) Process(
	ctx context.Context,
	jobID pgtype.UUID,
) (ClaimDisposition, error) {
	claim, err := processor.Claim(ctx, jobID)
	if err != nil {
		return "", err
	}
	if claim.Disposition != ClaimReady {
		return claim.Disposition, nil
	}
	job := claim.Job

	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRenewal := make(chan struct{})
	renewalDone := make(chan error, 1)
	go func() {
		renewalErr := processor.renewLease(workCtx, job, stopRenewal)
		if renewalErr != nil {
			cancel()
		}
		renewalDone <- renewalErr
	}()

	reader, writer := io.Pipe()
	renderDone := make(chan error, 1)
	go func() {
		renderErr := processor.renderer.Render(workCtx, job, writer)
		_ = writer.CloseWithError(renderErr)
		renderDone <- renderErr
	}()

	objectKey, uploadErr := processor.objects.Upload(workCtx, job, reader)
	if uploadErr != nil {
		// If upload returns before consuming the stream, unblock the renderer.
		cancel()
		_ = reader.CloseWithError(uploadErr)
	} else {
		_ = reader.Close()
	}
	renderErr := <-renderDone
	close(stopRenewal)
	renewalErr := <-renewalDone

	if renewalErr != nil {
		return "", renewalErr
	}
	var processingErr error
	switch {
	case renderErr != nil && (uploadErr == nil || errors.Is(uploadErr, renderErr)):
		processingErr = fmt.Errorf("render audit export: %w", renderErr)
	case uploadErr != nil:
		processingErr = fmt.Errorf("upload audit export: %w", uploadErr)
	case renderErr != nil:
		processingErr = fmt.Errorf("render audit export: %w", renderErr)
	case objectKey == "":
		processingErr = ErrEmptyExportObjectKey
	}
	if processingErr != nil {
		return processor.retryOrFail(ctx, job, processingErr)
	}

	rows, err := processor.jobs.CompleteAuditExportJob(ctx, store.CompleteAuditExportJobParams{
		JobID:           job.ID,
		AttemptCount:    job.AttemptCount,
		OutputObjectKey: &objectKey,
	})
	if err != nil {
		return "", fmt.Errorf("complete audit export job: %w", err)
	}
	if rows != 1 {
		return "", ErrExportClaimLost
	}
	return ClaimCompleted, nil
}

func (processor *Processor) retryOrFail(
	ctx context.Context,
	job store.ExportJob,
	cause error,
) (ClaimDisposition, error) {
	if job.AttemptCount < MaxExportAttempts || ctx.Err() != nil {
		return "", cause
	}
	rows, err := processor.jobs.FailAuditExportJob(ctx, store.FailAuditExportJobParams{
		JobID: job.ID, AttemptCount: job.AttemptCount,
		LastErrorCode: stringPointer("retry_exhausted"),
	})
	if err != nil {
		return "", errors.Join(cause, fmt.Errorf("fail exhausted audit export job: %w", err))
	}
	if rows != 1 {
		return "", errors.Join(cause, ErrExportClaimLost)
	}
	return ClaimFailed, nil
}

// ReconcileExhausted handles a process crash on its last allowed attempt:
// even if SQS has already redriven the message, the expired DB job becomes
// terminal rather than remaining "running" forever.
func (processor *Processor) ReconcileExhausted(ctx context.Context) (int, error) {
	if processor == nil || processor.jobs == nil {
		return 0, ErrInvalidProcessorConfiguration
	}
	jobIDs, err := processor.jobs.FailExpiredExhaustedAuditExportJobs(ctx, MaxExportAttempts)
	if err != nil {
		return 0, fmt.Errorf("reconcile exhausted audit exports: %w", err)
	}
	return len(jobIDs), nil
}

func stringPointer(value string) *string { return &value }

func (processor *Processor) renewLease(
	ctx context.Context,
	job store.ExportJob,
	stop <-chan struct{},
) error {
	ticker := time.NewTicker(processor.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			rows, err := processor.jobs.RenewAuditExportJobLease(
				ctx,
				store.RenewAuditExportJobLeaseParams{
					JobID:        job.ID,
					AttemptCount: job.AttemptCount,
					LeaseSeconds: processor.leaseSeconds,
				},
			)
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("renew audit export lease: %w", err)
			}
			if rows != 1 {
				return ErrExportClaimLost
			}
		}
	}
}

var _ JobProcessorStore = (*store.Queries)(nil)
var _ EventRenderer = (*Renderer)(nil)
