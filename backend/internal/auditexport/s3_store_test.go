package auditexport

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type recordingS3Uploader struct {
	input *transfermanager.UploadObjectInput
	body  string
	err   error
}

func (uploader *recordingS3Uploader) UploadObject(
	_ context.Context,
	input *transfermanager.UploadObjectInput,
	_ ...func(*transfermanager.Options),
) (*transfermanager.UploadObjectOutput, error) {
	uploader.input = input
	if uploader.err != nil {
		return nil, uploader.err
	}
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	uploader.body = string(body)
	return &transfermanager.UploadObjectOutput{}, nil
}

func testClaimedExportJob(format string) store.ExportJob {
	job := testExportJob(format)
	job.Status = "running"
	job.AttemptCount = 2
	return job
}

func TestS3ObjectStoreUploadsWithJobBoundKey(t *testing.T) {
	tests := []struct {
		format      string
		contentType string
	}{
		{format: "csv", contentType: "text/csv; charset=utf-8"},
		{format: "json", contentType: "application/json"},
	}
	for _, test := range tests {
		t.Run(test.format, func(t *testing.T) {
			uploader := &recordingS3Uploader{}
			objectStore, err := NewS3ObjectStore(uploader, "private-audit-exports")
			if err != nil {
				t.Fatalf("create object store: %v", err)
			}
			job := testClaimedExportJob(test.format)
			payload := "rendered audit events"
			key, err := objectStore.Upload(context.Background(), job, strings.NewReader(payload))
			if err != nil {
				t.Fatalf("upload export: %v", err)
			}
			wantKey := "audit-exports/" + job.TenantID.String() + "/" +
				job.ID.String() + "/attempt-2." + test.format
			if key != wantKey || uploader.input == nil ||
				aws.ToString(uploader.input.Bucket) != "private-audit-exports" ||
				aws.ToString(uploader.input.Key) != wantKey ||
				aws.ToString(uploader.input.ContentType) != test.contentType ||
				uploader.input.ACL != "" || uploader.body != payload {
				t.Fatalf("unexpected S3 upload: key=%q, input=%+v, body=%q", key, uploader.input, uploader.body)
			}

			job.AttemptCount++
			retryKey, err := objectStore.Upload(context.Background(), job, strings.NewReader(payload))
			if err != nil || retryKey == key || !strings.Contains(retryKey, "/attempt-3.") {
				t.Fatalf("retry must use a distinct object key: key=%q, err=%v", retryKey, err)
			}
		})
	}
}

func TestS3ObjectStoreRejectsInvalidConfigurationAndJobs(t *testing.T) {
	if _, err := NewS3ObjectStore(nil, "bucket"); !errors.Is(err, ErrInvalidS3ObjectStore) {
		t.Fatalf("expected missing uploader error, got %v", err)
	}
	if _, err := NewS3ObjectStore(&recordingS3Uploader{}, " "); !errors.Is(err, ErrInvalidS3ObjectStore) {
		t.Fatalf("expected missing bucket error, got %v", err)
	}

	tests := []struct {
		name   string
		change func(*store.ExportJob)
	}{
		{name: "missing job ID", change: func(job *store.ExportJob) { job.ID = pgtype.UUID{} }},
		{name: "missing tenant ID", change: func(job *store.ExportJob) { job.TenantID = pgtype.UUID{} }},
		{name: "missing claim", change: func(job *store.ExportJob) { job.AttemptCount = 0 }},
		{name: "not running", change: func(job *store.ExportJob) { job.Status = "queued" }},
		{name: "unsupported format", change: func(job *store.ExportJob) { job.Format = "xml" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uploader := &recordingS3Uploader{}
			objectStore, err := NewS3ObjectStore(uploader, "private-audit-exports")
			if err != nil {
				t.Fatalf("create object store: %v", err)
			}
			job := testClaimedExportJob("csv")
			test.change(&job)
			key, err := objectStore.Upload(context.Background(), job, strings.NewReader("data"))
			if key != "" || !errors.Is(err, ErrInvalidS3ExportJob) || uploader.input != nil {
				t.Fatalf("invalid job caused upload: key=%q, err=%v, input=%+v", key, err, uploader.input)
			}
		})
	}
}

func TestS3ObjectStorePropagatesUploadFailure(t *testing.T) {
	uploadErr := errors.New("S3 unavailable")
	uploader := &recordingS3Uploader{err: uploadErr}
	objectStore, err := NewS3ObjectStore(uploader, "private-audit-exports")
	if err != nil {
		t.Fatalf("create object store: %v", err)
	}
	key, err := objectStore.Upload(
		context.Background(),
		testClaimedExportJob("csv"),
		strings.NewReader("data"),
	)
	if key != "" || !errors.Is(err, uploadErr) {
		t.Fatalf("expected upload failure and no object key: key=%q, err=%v", key, err)
	}
}
