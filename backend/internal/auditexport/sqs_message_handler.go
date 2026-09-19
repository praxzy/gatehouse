package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrInvalidJobMessage = errors.New("invalid audit export message")
	ErrMessageDeferred   = errors.New("audit export message not completed")
)

type JobProcessor interface {
	Process(context.Context, pgtype.UUID) (ClaimDisposition, error)
}

type messageDeleter interface {
	DeleteMessage(context.Context, *sqs.DeleteMessageInput, ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
}

type SQSMessageHandler struct {
	processor JobProcessor
	deleter   messageDeleter
	queueURL  string
}

func NewSQSMessageHandler(processor JobProcessor, deleter messageDeleter, queueURL string) (*SQSMessageHandler, error) {
	if processor == nil || deleter == nil || strings.TrimSpace(queueURL) == "" {
		return nil, ErrInvalidProcessorConfiguration
	}
	return &SQSMessageHandler{processor: processor, deleter: deleter, queueURL: queueURL}, nil
}

func (handler *SQSMessageHandler) Handle(ctx context.Context, message sqstypes.Message) error {
	if message.ReceiptHandle == nil || *message.ReceiptHandle == "" {
		return ErrInvalidJobMessage
	}
	jobID, err := parseJobMessage(aws.ToString(message.Body))
	if err != nil {
		return err // Do not delete; bounded SQS redrive can send it to the DLQ.
	}

	disposition, err := handler.processor.Process(ctx, jobID)
	if err != nil {
		return err
	}
	if disposition != ClaimCompleted {
		return fmt.Errorf("%w: %s", ErrMessageDeferred, disposition)
	}

	_, err = handler.deleter.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(handler.queueURL),
		ReceiptHandle: message.ReceiptHandle,
	})
	return err
}

func parseJobMessage(body string) (pgtype.UUID, error) {
	if len(body) == 0 || len(body) > 1024 {
		return pgtype.UUID{}, ErrInvalidJobMessage
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()

	var payload struct {
		JobID string `json:"job_id"`
	}
	if err := decoder.Decode(&payload); err != nil {
		return pgtype.UUID{}, fmt.Errorf("%w: %v", ErrInvalidJobMessage, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return pgtype.UUID{}, ErrInvalidJobMessage
	}
	parsed, err := uuid.Parse(payload.JobID)
	if err != nil {
		return pgtype.UUID{}, ErrInvalidJobMessage
	}
	return pgtype.UUID{Bytes: [16]byte(parsed), Valid: true}, nil
}