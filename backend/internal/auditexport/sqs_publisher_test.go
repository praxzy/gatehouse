package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeSQSSender struct {
	input *sqs.SendMessageInput
	err   error
	calls int
}

func (sender *fakeSQSSender) SendMessage(
	_ context.Context,
	input *sqs.SendMessageInput,
	_ ...func(*sqs.Options),
) (*sqs.SendMessageOutput, error) {
	sender.calls++
	sender.input = input
	if sender.err != nil {
		return nil, sender.err
	}
	return &sqs.SendMessageOutput{}, nil
}

func TestSQSPublisherSendsOnlyJobID(t *testing.T) {
	sender := &fakeSQSSender{}
	publisher, err := NewSQSPublisher(sender, "https://sqs.example.test/exports")
	if err != nil {
		t.Fatal(err)
	}

	id := uuid.MustParse("11111111-2222-4333-8444-555555555555")
	err = publisher.PublishJob(context.Background(), pgtype.UUID{
		Bytes: [16]byte(id),
		Valid: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if sender.calls != 1 ||
		aws.ToString(sender.input.QueueUrl) != "https://sqs.example.test/exports" {
		t.Fatalf("unexpected SQS send: %+v", sender.input)
	}

	var body map[string]any
	if err := json.Unmarshal(
		[]byte(aws.ToString(sender.input.MessageBody)),
		&body,
	); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body["job_id"] != id.String() {
		t.Fatalf("message must contain only job_id: %+v", body)
	}
}

func TestSQSPublisherRejectsInvalidIDAndPropagatesSendError(t *testing.T) {
	sender := &fakeSQSSender{}
	publisher, err := NewSQSPublisher(sender, "https://sqs.example.test/exports")
	if err != nil {
		t.Fatal(err)
	}

	if err := publisher.PublishJob(context.Background(), pgtype.UUID{}); err == nil {
		t.Fatal("expected invalid job ID error")
	}
	if sender.calls != 0 {
		t.Fatal("invalid job ID was sent")
	}

	sendFailure := errors.New("SQS unavailable")
	sender.err = sendFailure
	err = publisher.PublishJob(context.Background(), pgtype.UUID{
		Bytes: [16]byte{1},
		Valid: true,
	})
	if !errors.Is(err, sendFailure) {
		t.Fatalf("expected wrapped SQS error, got %v", err)
	}
}
