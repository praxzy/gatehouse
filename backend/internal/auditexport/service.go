package auditexport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var (
	ErrInvalidServiceConfiguration = errors.New(
		"invalid audit export service configuration",
	)
	ErrExportForbidden      = errors.New("audit export forbidden")
	ErrInvalidExportRequest = errors.New(
		"invalid audit export request",
	)
)

// JobPublisher publishes only a job ID. The worker must reload all tenant and
// filter data from the database rather than trusting queue-message fields.
type JobPublisher interface {
	PublishJob(context.Context, pgtype.UUID) error
}

type Service struct {
	pool        *pgxpool.Pool
	queries     *store.Queries
	auditWriter audit.EventWriter
	publisher   JobPublisher
}

type CreateInput struct {
	Format        string
	ActorUserID   pgtype.UUID
	ApplicationID pgtype.UUID
	EventType     string
	Outcome       string
	TimeFrom      time.Time
	TimeUntil     time.Time
}

type CreateResult struct {
	Job      store.ExportJob
	Enqueued bool
}

func NewService(
	pool *pgxpool.Pool,
	auditWriter audit.EventWriter,
	publisher JobPublisher,
) (*Service, error) {
	if pool == nil || auditWriter == nil || publisher == nil {
		return nil, ErrInvalidServiceConfiguration
	}

	return &Service{
		pool:        pool,
		queries:     store.New(pool),
		auditWriter: auditWriter,
		publisher:   publisher,
	}, nil
}

func (service *Service) Create(
	ctx context.Context,
	session auth.SessionContext,
	input CreateInput,
) (CreateResult, error) {
	if !session.HasPermission(auth.PermissionAuditExport) ||
		!session.TenantID.Valid ||
		!session.MembershipID.Valid ||
		!session.UserID.Valid {
		return CreateResult{}, ErrExportForbidden
	}
	if err := validateCreateInput(input); err != nil {
		return CreateResult{}, err
	}

	transaction, err := service.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return CreateResult{}, fmt.Errorf(
			"begin audit export transaction: %w",
			err,
		)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()

	queries := service.queries.WithTx(transaction)
	job, err := queries.CreateAuditExportJob(
		ctx,
		store.CreateAuditExportJobParams{
			TenantID:                session.TenantID,
			RequestedByMembershipID: session.MembershipID,
			Format:                  input.Format,
			FilterActorUserID:       input.ActorUserID,
			FilterApplicationID:     input.ApplicationID,
			FilterEventType:         optionalString(input.EventType),
			FilterOutcome:           optionalString(input.Outcome),
			TimeFrom:                optionalTime(input.TimeFrom),
			TimeUntil:               optionalTime(input.TimeUntil),
		},
	)
	if err != nil {
		return CreateResult{}, fmt.Errorf(
			"create audit export job: %w",
			err,
		)
	}

	_, err = service.auditWriter.Write(ctx, queries, audit.Event{
		TenantID:          session.TenantID,
		ActorKind:         audit.ActorUser,
		ActorUserID:       session.UserID,
		ActorMembershipID: session.MembershipID,
		SessionID:         session.SessionID,
		Type:              audit.EventAuditExportRequested,
		Outcome:           audit.OutcomeSuccess,
		SubjectType:       "export_job",
		SubjectID:         job.ID,
		Metadata: audit.Metadata{
			"format": input.Format,
		},
	})
	if err != nil {
		return CreateResult{}, fmt.Errorf(
			"audit export job creation: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return CreateResult{}, fmt.Errorf(
			"commit audit export job: %w",
			err,
		)
	}

	// The committed queued job is the durable retry record. Publication and the
	// enqueued_at update cannot share a transaction with SQS, so a failure here
	// must not erase the job; DispatchPending will retry it.
	enqueued, err := service.publishAndMark(ctx, job.ID)
	if err != nil {
		slog.Warn(
			"audit export enqueue deferred",
			"job_id", job.ID,
			"error", err,
		)
	}

	return CreateResult{Job: job, Enqueued: enqueued}, nil
}

// DispatchPending retries committed jobs whose queue publication has not been
// recorded. A duplicate publication is safe because workers claim jobs by ID.
func (service *Service) DispatchPending(
	ctx context.Context,
	batchSize int32,
) (int, error) {
	if batchSize < 1 || batchSize > 100 {
		return 0, ErrInvalidExportRequest
	}

	jobIDs, err := service.queries.ListPendingAuditExportEnqueues(ctx, batchSize)
	if err != nil {
		return 0, fmt.Errorf(
			"list pending audit export jobs: %w",
			err,
		)
	}

	dispatched := 0
	for _, jobID := range jobIDs {
		if _, err := service.publishAndMark(ctx, jobID); err != nil {
			return dispatched, fmt.Errorf(
				"dispatch audit export job: %w",
				err,
			)
		}
		dispatched++
	}

	return dispatched, nil
}

func (service *Service) publishAndMark(
	ctx context.Context,
	jobID pgtype.UUID,
) (bool, error) {
	if err := service.publisher.PublishJob(ctx, jobID); err != nil {
		return false, err
	}
	if _, err := service.queries.MarkAuditExportJobEnqueued(ctx, jobID); err != nil {
		return false, err
	}
	return true, nil
}

func validateCreateInput(input CreateInput) error {
	if input.Format != "csv" && input.Format != "json" {
		return ErrInvalidExportRequest
	}
	if !input.TimeFrom.IsZero() && !input.TimeUntil.IsZero() &&
		!input.TimeUntil.After(input.TimeFrom) {
		return ErrInvalidExportRequest
	}
	if input.EventType != "" {
		known := false
		for _, eventType := range audit.EventTypes() {
			if input.EventType == string(eventType) {
				known = true
				break
			}
		}
		if !known {
			return ErrInvalidExportRequest
		}
	}
	if input.Outcome != "" &&
		input.Outcome != string(audit.OutcomeSuccess) &&
		input.Outcome != string(audit.OutcomeFailure) &&
		input.Outcome != string(audit.OutcomeDenied) {
		return ErrInvalidExportRequest
	}
	return nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func optionalTime(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}
