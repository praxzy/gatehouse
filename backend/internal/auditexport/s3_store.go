package auditexport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var (
	ErrInvalidS3ObjectStore = errors.New("invalid S3 object store configuration")
	ErrInvalidS3ExportJob   = errors.New("invalid S3 audit export job")
)

// ObjectStore receives a claimed, database-loaded job and its rendered data.
// Queue messages must never supply the tenant, format, or object key.
type ObjectStore interface {
	Upload(context.Context, store.ExportJob, io.Reader) (string, error)
}

type s3ObjectUploader interface {
	UploadObject(
		context.Context,
		*transfermanager.UploadObjectInput,
		...func(*transfermanager.Options),
	) (*transfermanager.UploadObjectOutput, error)
}

type S3ObjectStore struct {
	uploader s3ObjectUploader
	bucket   string
}

func NewS3ObjectStore(uploader s3ObjectUploader, bucket string) (*S3ObjectStore, error) {
	if uploader == nil || strings.TrimSpace(bucket) == "" {
		return nil, ErrInvalidS3ObjectStore
	}
	return &S3ObjectStore{uploader: uploader, bucket: bucket}, nil
}

func (objectStore *S3ObjectStore) Upload(
	ctx context.Context,
	job store.ExportJob,
	body io.Reader,
) (string, error) {
	if objectStore == nil || objectStore.uploader == nil || body == nil {
		return "", ErrInvalidS3ObjectStore
	}
	if !job.ID.Valid || !job.TenantID.Valid || job.AttemptCount < 1 ||
		job.Status != "running" {
		return "", ErrInvalidS3ExportJob
	}

	var contentType string
	switch job.Format {
	case "csv":
		contentType = "text/csv; charset=utf-8"
	case "json":
		contentType = "application/json"
	default:
		return "", ErrInvalidS3ExportJob
	}

	objectKey := fmt.Sprintf(
		"audit-exports/%s/%s/attempt-%d.%s",
		job.TenantID.String(),
		job.ID.String(),
		job.AttemptCount,
		job.Format,
	)
	_, err := objectStore.uploader.UploadObject(
		ctx,
		&transfermanager.UploadObjectInput{
			Bucket:      aws.String(objectStore.bucket),
			Key:         aws.String(objectKey),
			Body:        body,
			ContentType: aws.String(contentType),
		},
	)
	if err != nil {
		return "", fmt.Errorf("upload audit export object: %w", err)
	}
	return objectKey, nil
}

var _ ObjectStore = (*S3ObjectStore)(nil)
var _ s3ObjectUploader = (*transfermanager.Client)(nil)
