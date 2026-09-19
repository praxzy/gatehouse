package auditexport

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type fakeJobClaimer struct {
	claimJob       store.ExportJob
	claimErr       error
	lookupJob      store.ExportJob
	lookupErr      error
	claimParams    store.ClaimAuditExportJobParams
	lookupID       pgtype.UUID
	claimCalls     int
	lookupCalls    int
	completeRows   int64
	completeErr    error
	completeParams store.CompleteAuditExportJobParams
	completeCalls  int
	renewRows      int64
	renewErr       error
	renewParams    store.RenewAuditExportJobLeaseParams
	renewCalls     int
	renewNotify    chan struct{}
	failRows       int64
	failErr        error
	failParams     store.FailAuditExportJobParams
	failCalls      int
	reconcileIDs   []pgtype.UUID
	reconcileErr   error
	reconcileLimit int32
}

func (fake *fakeJobClaimer) ClaimAuditExportJob(
	_ context.Context,
	params store.ClaimAuditExportJobParams,
) (store.ExportJob, error) {
	fake.claimCalls++
	fake.claimParams = params
	return fake.claimJob, fake.claimErr
}

func (fake *fakeJobClaimer) GetAuditExportJobByID(
	_ context.Context,
	jobID pgtype.UUID,
) (store.ExportJob, error) {
	fake.lookupCalls++
	fake.lookupID = jobID
	return fake.lookupJob, fake.lookupErr
}

func (fake *fakeJobClaimer) RenewAuditExportJobLease(
	_ context.Context,
	params store.RenewAuditExportJobLeaseParams,
) (int64, error) {
	fake.renewCalls++
	fake.renewParams = params
	if fake.renewCalls == 1 && fake.renewNotify != nil {
		close(fake.renewNotify)
	}
	return fake.renewRows, fake.renewErr
}

func (fake *fakeJobClaimer) CompleteAuditExportJob(
	_ context.Context,
	params store.CompleteAuditExportJobParams,
) (int64, error) {
	fake.completeCalls++
	fake.completeParams = params
	return fake.completeRows, fake.completeErr
}

func (fake *fakeJobClaimer) FailAuditExportJob(
	_ context.Context,
	params store.FailAuditExportJobParams,
) (int64, error) {
	fake.failCalls++
	fake.failParams = params
	return fake.failRows, fake.failErr
}

func (fake *fakeJobClaimer) FailExpiredExhaustedAuditExportJobs(
	_ context.Context,
	maxAttempts int32,
) ([]pgtype.UUID, error) {
	fake.reconcileLimit = maxAttempts
	return fake.reconcileIDs, fake.reconcileErr
}

type eventRendererFunc func(context.Context, store.ExportJob, io.Writer) error

func (render eventRendererFunc) Render(
	ctx context.Context,
	job store.ExportJob,
	output io.Writer,
) error {
	return render(ctx, job, output)
}

type objectStoreFunc func(context.Context, store.ExportJob, io.Reader) (string, error)

func (upload objectStoreFunc) Upload(
	ctx context.Context,
	job store.ExportJob,
	body io.Reader,
) (string, error) {
	return upload(ctx, job, body)
}

func newClaimTestProcessor(t *testing.T, fake *fakeJobClaimer) *Processor {
	t.Helper()
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(context.Context, store.ExportJob, io.Writer) error { return nil }),
		objectStoreFunc(func(context.Context, store.ExportJob, io.Reader) (string, error) { return "", nil }),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	return processor
}

func testProcessorJob() store.ExportJob {
	job := testClaimedExportJob("csv")
	job.LeaseExpiresAt = pgtype.Timestamptz{
		Time:  time.Now().UTC().Add(time.Minute),
		Valid: true,
	}
	return job
}

func TestProcessorClaimsDatabaseBoundJob(t *testing.T) {
	job := testProcessorJob()
	outcome := "success"
	job.FilterOutcome = &outcome
	fake := &fakeJobClaimer{claimJob: job}
	processor := newClaimTestProcessor(t, fake)

	result, err := processor.Claim(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("claim export job: %v", err)
	}
	if result.Disposition != ClaimReady || result.Job.ID != job.ID ||
		result.Job.TenantID != job.TenantID || result.Job.FilterOutcome != job.FilterOutcome ||
		fake.claimCalls != 1 || fake.lookupCalls != 0 ||
		fake.claimParams.JobID != job.ID || fake.claimParams.LeaseSeconds != 60 {
		t.Fatalf("unexpected claim result: result=%+v, store=%+v", result, fake)
	}
}

func TestProcessorClassifiesUnclaimedJobs(t *testing.T) {
	baseJob := testProcessorJob()
	tests := []struct {
		name        string
		status      string
		lookupErr   error
		disposition ClaimDisposition
	}{
		{name: "completed duplicate", status: "completed", disposition: ClaimCompleted},
		{name: "active lease", status: "running", disposition: ClaimBusy},
		{name: "queued race", status: "queued", disposition: ClaimBusy},
		{name: "terminal failure", status: "failed", disposition: ClaimFailed},
		{name: "unknown job", lookupErr: pgx.ErrNoRows, disposition: ClaimUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			job := baseJob
			job.Status = test.status
			fake := &fakeJobClaimer{
				claimErr:  pgx.ErrNoRows,
				lookupJob: job,
				lookupErr: test.lookupErr,
			}
			processor := newClaimTestProcessor(t, fake)
			result, err := processor.Claim(context.Background(), baseJob.ID)
			if err != nil || result.Disposition != test.disposition ||
				fake.claimCalls != 1 || fake.lookupCalls != 1 || fake.lookupID != baseJob.ID {
				t.Fatalf("unexpected result: result=%+v, err=%v, store=%+v", result, err, fake)
			}
			if test.disposition == ClaimUnknown && result.Job.ID.Valid {
				t.Fatalf("unknown job must not supply tenant data: %+v", result.Job)
			}
		})
	}
}

func TestProcessorRejectsInvalidInputAndStoreErrors(t *testing.T) {
	noOpRenderer := eventRendererFunc(func(context.Context, store.ExportJob, io.Writer) error { return nil })
	noOpStore := objectStoreFunc(func(context.Context, store.ExportJob, io.Reader) (string, error) { return "", nil })
	if _, err := NewProcessor(nil, noOpRenderer, noOpStore, 60); !errors.Is(err, ErrInvalidProcessorConfiguration) {
		t.Fatalf("expected missing store error, got %v", err)
	}
	if _, err := NewProcessor(&fakeJobClaimer{}, noOpRenderer, noOpStore, 0); !errors.Is(err, ErrInvalidProcessorConfiguration) {
		t.Fatalf("expected invalid lease error, got %v", err)
	}

	fake := &fakeJobClaimer{}
	processor := newClaimTestProcessor(t, fake)
	if _, err := processor.Claim(context.Background(), pgtype.UUID{}); !errors.Is(err, ErrInvalidExportJobID) {
		t.Fatalf("expected invalid ID error, got %v", err)
	}
	if fake.claimCalls != 0 {
		t.Fatal("invalid job ID reached the store")
	}

	storeErr := errors.New("database unavailable")
	fake.claimErr = storeErr
	if _, err := processor.Claim(context.Background(), testUUID(1)); !errors.Is(err, storeErr) {
		t.Fatalf("expected claim error, got %v", err)
	}
	fake.claimErr = pgx.ErrNoRows
	fake.lookupErr = storeErr
	if _, err := processor.Claim(context.Background(), testUUID(1)); !errors.Is(err, storeErr) {
		t.Fatalf("expected lookup error, got %v", err)
	}
}

func TestProcessorRejectsMismatchedClaim(t *testing.T) {
	job := testProcessorJob()
	fake := &fakeJobClaimer{claimJob: job}
	processor := newClaimTestProcessor(t, fake)
	if _, err := processor.Claim(context.Background(), testUUID(99)); !errors.Is(err, ErrInvalidClaimedExportJob) {
		t.Fatalf("expected mismatched claim rejection, got %v", err)
	}
}

func TestProcessorStreamsAndCompletesClaimedJob(t *testing.T) {
	job := testProcessorJob()
	fake := &fakeJobClaimer{claimJob: job, completeRows: 1}
	const payload = "rendered audit events"
	const objectKey = "audit-exports/tenant/job/attempt-2.csv"
	renderCalls := 0
	uploadCalls := 0
	renderer := eventRendererFunc(func(_ context.Context, received store.ExportJob, output io.Writer) error {
		renderCalls++
		if received.ID != job.ID || received.TenantID != job.TenantID {
			return errors.New("renderer received wrong database job")
		}
		_, err := io.WriteString(output, payload)
		return err
	})
	objects := objectStoreFunc(func(_ context.Context, received store.ExportJob, body io.Reader) (string, error) {
		uploadCalls++
		if received.ID != job.ID || received.AttemptCount != job.AttemptCount {
			return "", errors.New("object store received wrong claim")
		}
		data, err := io.ReadAll(body)
		if err != nil || string(data) != payload {
			return "", errors.New("unexpected upload body")
		}
		return objectKey, nil
	})
	processor, err := NewProcessor(fake, renderer, objects, 60)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}

	disposition, err := processor.Process(context.Background(), job.ID)
	if err != nil || disposition != ClaimCompleted || renderCalls != 1 || uploadCalls != 1 ||
		fake.completeCalls != 1 || fake.completeParams.JobID != job.ID ||
		fake.completeParams.AttemptCount != job.AttemptCount ||
		fake.completeParams.OutputObjectKey == nil ||
		*fake.completeParams.OutputObjectKey != objectKey {
		t.Fatalf("unexpected completion: disposition=%s, err=%v, store=%+v", disposition, err, fake)
	}
}

func TestProcessorSkipsUnclaimedJobs(t *testing.T) {
	job := testProcessorJob()
	tests := []struct {
		name        string
		status      string
		lookupErr   error
		disposition ClaimDisposition
	}{
		{name: "completed duplicate", status: "completed", disposition: ClaimCompleted},
		{name: "active lease", status: "running", disposition: ClaimBusy},
		{name: "terminal failure", status: "failed", disposition: ClaimFailed},
		{name: "unknown message", lookupErr: pgx.ErrNoRows, disposition: ClaimUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lookup := job
			lookup.Status = test.status
			fake := &fakeJobClaimer{
				claimErr: pgx.ErrNoRows, lookupJob: lookup, lookupErr: test.lookupErr,
			}
			renderCalls := 0
			uploadCalls := 0
			processor, err := NewProcessor(
				fake,
				eventRendererFunc(func(context.Context, store.ExportJob, io.Writer) error {
					renderCalls++
					return errors.New("unclaimed job reached renderer")
				}),
				objectStoreFunc(func(context.Context, store.ExportJob, io.Reader) (string, error) {
					uploadCalls++
					return "", errors.New("unclaimed job reached object storage")
				}),
				60,
			)
			if err != nil {
				t.Fatalf("create processor: %v", err)
			}
			disposition, err := processor.Process(context.Background(), job.ID)
			if err != nil || disposition != test.disposition || fake.completeCalls != 0 ||
				renderCalls != 0 || uploadCalls != 0 {
				t.Fatalf("unexpected unclaimed outcome: disposition=%s, err=%v", disposition, err)
			}
		})
	}
}

func TestProcessorDoesNotCompleteFailedRenderOrUpload(t *testing.T) {
	job := testProcessorJob()
	tests := []struct {
		name     string
		renderer eventRendererFunc
		objects  objectStoreFunc
		wantErr  error
	}{
		{
			name:    "render failure",
			wantErr: errors.New("render failed"),
		},
		{
			name:    "upload failure",
			wantErr: errors.New("upload failed"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeJobClaimer{claimJob: job, completeRows: 1}
			renderer := eventRendererFunc(func(_ context.Context, _ store.ExportJob, output io.Writer) error {
				if _, err := io.WriteString(output, "partial"); err != nil {
					return err
				}
				if test.name == "render failure" {
					return test.wantErr
				}
				return nil
			})
			objects := objectStoreFunc(func(_ context.Context, _ store.ExportJob, body io.Reader) (string, error) {
				if test.name == "upload failure" {
					// Returning without reading must still unblock the renderer.
					return "", test.wantErr
				}
				_, err := io.ReadAll(body)
				return "", err
			})
			processor, err := NewProcessor(fake, renderer, objects, 60)
			if err != nil {
				t.Fatalf("create processor: %v", err)
			}
			disposition, err := processor.Process(context.Background(), job.ID)
			if disposition != "" || !errors.Is(err, test.wantErr) || fake.completeCalls != 0 {
				t.Fatalf("failed job was completed: disposition=%s, err=%v, store=%+v", disposition, err, fake)
			}
		})
	}
}

func TestProcessorFailsAfterFinalAttempt(t *testing.T) {
	job := testProcessorJob()
	job.AttemptCount = MaxExportAttempts
	fake := &fakeJobClaimer{claimJob: job, failRows: 1}
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(_ context.Context, _ store.ExportJob, output io.Writer) error {
			_, err := io.WriteString(output, "partial")
			return err
		}),
		objectStoreFunc(func(_ context.Context, _ store.ExportJob, body io.Reader) (string, error) {
			_, _ = io.Copy(io.Discard, body)
			return "", errors.New("storage unavailable")
		}),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	disposition, err := processor.Process(context.Background(), job.ID)
	if err != nil || disposition != ClaimFailed || fake.failCalls != 1 ||
		fake.completeCalls != 0 || fake.failParams.JobID != job.ID ||
		fake.failParams.AttemptCount != MaxExportAttempts ||
		fake.failParams.LastErrorCode == nil || *fake.failParams.LastErrorCode != "retry_exhausted" {
		t.Fatalf("final attempt did not fail the job: disposition=%s, err=%v, store=%+v", disposition, err, fake)
	}
}

func TestProcessorDoesNotRenderExhaustedClaim(t *testing.T) {
	job := testProcessorJob()
	job.AttemptCount = MaxExportAttempts + 1
	fake := &fakeJobClaimer{claimJob: job, failRows: 1}
	rendered := false
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(context.Context, store.ExportJob, io.Writer) error {
			rendered = true
			return nil
		}),
		objectStoreFunc(func(context.Context, store.ExportJob, io.Reader) (string, error) {
			t.Fatal("exhausted job reached object store")
			return "", nil
		}),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	disposition, err := processor.Process(context.Background(), job.ID)
	if err != nil || disposition != ClaimFailed || rendered || fake.failCalls != 1 {
		t.Fatalf("exhausted claim was processed: disposition=%s, err=%v, rendered=%v", disposition, err, rendered)
	}
}

func TestProcessorReconcilesExpiredFinalAttempt(t *testing.T) {
	job := testProcessorJob()
	fake := &fakeJobClaimer{reconcileIDs: []pgtype.UUID{job.ID}}
	processor := newClaimTestProcessor(t, fake)
	count, err := processor.ReconcileExhausted(context.Background())
	if err != nil || count != 1 || fake.reconcileLimit != MaxExportAttempts {
		t.Fatalf("failed to reconcile final attempt: count=%d, err=%v, limit=%d", count, err, fake.reconcileLimit)
	}
}

func TestProcessorRejectsStaleCompletion(t *testing.T) {
	job := testProcessorJob()
	fake := &fakeJobClaimer{claimJob: job, completeRows: 0}
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(_ context.Context, _ store.ExportJob, output io.Writer) error {
			_, err := io.WriteString(output, "data")
			return err
		}),
		objectStoreFunc(func(_ context.Context, _ store.ExportJob, body io.Reader) (string, error) {
			_, err := io.Copy(io.Discard, body)
			return "object-key", err
		}),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	if _, err := processor.Process(context.Background(), job.ID); !errors.Is(err, ErrExportClaimLost) {
		t.Fatalf("expected stale completion rejection, got %v", err)
	}
}

func TestProcessorRenewsLeaseDuringLongUpload(t *testing.T) {
	job := testProcessorJob()
	renewed := make(chan struct{})
	fake := &fakeJobClaimer{claimJob: job, completeRows: 1, renewRows: 1, renewNotify: renewed}
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(_ context.Context, _ store.ExportJob, output io.Writer) error {
			_, err := io.WriteString(output, "data")
			return err
		}),
		objectStoreFunc(func(ctx context.Context, _ store.ExportJob, body io.Reader) (string, error) {
			select {
			case <-renewed:
			case <-ctx.Done():
				return "", ctx.Err()
			}
			data, err := io.ReadAll(body)
			if err != nil || string(data) != "data" {
				return "", errors.New("unexpected upload data")
			}
			return "object-key", nil
		}),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	processor.renewInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	disposition, err := processor.Process(ctx, job.ID)
	if err != nil || disposition != ClaimCompleted || fake.renewCalls < 1 ||
		fake.renewParams.AttemptCount != job.AttemptCount ||
		fake.renewParams.JobID != job.ID || fake.renewParams.LeaseSeconds != 60 {
		t.Fatalf("lease was not renewed: disposition=%s, err=%v, store=%+v", disposition, err, fake)
	}
}

func TestProcessorStopsWhenLeaseIsLost(t *testing.T) {
	job := testProcessorJob()
	fake := &fakeJobClaimer{claimJob: job, renewRows: 0}
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(ctx context.Context, _ store.ExportJob, _ io.Writer) error {
			<-ctx.Done()
			return ctx.Err()
		}),
		objectStoreFunc(func(ctx context.Context, _ store.ExportJob, _ io.Reader) (string, error) {
			<-ctx.Done()
			return "", ctx.Err()
		}),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	processor.renewInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := processor.Process(ctx, job.ID); !errors.Is(err, ErrExportClaimLost) ||
		fake.completeCalls != 0 {
		t.Fatalf("lost lease still completed job: err=%v, store=%+v", err, fake)
	}
}

func TestProcessorUploadDoesNotAssumeEmptyObjectKey(t *testing.T) {
	job := testProcessorJob()
	fake := &fakeJobClaimer{claimJob: job, completeRows: 1}
	processor, err := NewProcessor(
		fake,
		eventRendererFunc(func(_ context.Context, _ store.ExportJob, output io.Writer) error {
			_, err := io.WriteString(output, strings.Repeat("x", 2))
			return err
		}),
		objectStoreFunc(func(_ context.Context, _ store.ExportJob, body io.Reader) (string, error) {
			_, err := io.Copy(io.Discard, body)
			return "", err
		}),
		60,
	)
	if err != nil {
		t.Fatalf("create processor: %v", err)
	}
	if _, err := processor.Process(context.Background(), job.ID); !errors.Is(err, ErrEmptyExportObjectKey) ||
		fake.completeCalls != 0 {
		t.Fatalf("empty object key completed job: err=%v, store=%+v", err, fake)
	}
}
