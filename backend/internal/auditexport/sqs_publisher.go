package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/google/uuid"
)

var ErrInvalidSQSPublisher = errors.New("invalid SQS publisher configuration")

type sqsSender interface {
	SendMessage(
		context.Context,
		*sqs.SendMessageInput,
		...func(*sqs.Options),
	) (*sqs.SendMessageOutput, error)
}

type SQSPublisher struct {
	sender   sqsSender
	queueURL string
}

func NewSQSPublisher(sender sqsSender, queueURL string) (*SQSPublisher, error) {
	if sender == nil || strings.TrimSpace(queueURL) == "" {
		return nil, ErrInvalidSQSPublisher
	}
	return &SQSPublisher{sender: sender, queueURL: queueURL}, nil
}

func (publisher *SQSPublisher) PublishJob(
	ctx context.Context,
	jobID pgtype.UUID,
) error {
	if !jobID.Valid {
		return errors.New("invalid audit export job ID")
	}

	body, err := json.Marshal(struct {
		JobID string `json:"job_id"`
	}{
		JobID: uuid.UUID(jobID.Bytes).String(),
	})
	if err != nil {
		return fmt.Errorf("encode export job message: %w", err)
	}

	_, err = publisher.sender.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    aws.String(publisher.queueURL),
		MessageBody: aws.String(string(body)),
	})
	if err != nil {
		return fmt.Errorf("send export job message: %w", err)
	}
	return nil
}