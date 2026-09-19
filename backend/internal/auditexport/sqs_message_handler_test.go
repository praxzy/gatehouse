package auditexport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/jackc/pgx/v5/pgtype"
)

type fakeMessageProcessor struct {
	disposition ClaimDisposition
	err         error
	jobID       pgtype.UUID
	calls       int
}

func (fake *fakeMessageProcessor) Process(
	_ context.Context,
	jobID pgtype.UUID,
) (ClaimDisposition, error) {
	fake.calls++
	fake.jobID = jobID
	return fake.disposition, fake.err
}

type fakeMessageDeleter struct {
	input *sqs.DeleteMessageInput
	err   error
	calls int
}

func (fake *fakeMessageDeleter) DeleteMessage(
	_ context.Context,
	input *sqs.DeleteMessageInput,
	_ ...func(*sqs.Options),
) (*sqs.DeleteMessageOutput, error) {
	fake.calls++
	fake.input = input
	if fake.err != nil {
		return nil, fake.err
	}
	return &sqs.DeleteMessageOutput{}, nil
}

func testJobMessage(jobID pgtype.UUID) sqstypes.Message {
	return sqstypes.Message{
		Body:          aws.String(fmt.Sprintf(`{"job_id":%q}`, jobID.String())),
		ReceiptHandle: aws.String("receipt-1"),
	}
}

func TestSQSMessageHandlerDeletesCompletedAndRedeliveredJobs(t *testing.T) {
	jobID := testUUID(17)
	processor := &fakeMessageProcessor{disposition: ClaimCompleted}
	deleter := &fakeMessageDeleter{}
	handler, err := NewSQSMessageHandler(processor, deleter, "queue-url")
	if err != nil {
		t.Fatalf("create message handler: %v", err)
	}

	message := testJobMessage(jobID)
	for range 2 {
		if err := handler.Handle(context.Background(), message); err != nil {
			t.Fatalf("handle completed message: %v", err)
		}
	}
	if processor.calls != 2 || processor.jobID != jobID || deleter.calls != 2 ||
		deleter.input == nil || aws.ToString(deleter.input.QueueUrl) != "queue-url" ||
		aws.ToString(deleter.input.ReceiptHandle) != "receipt-1" {
		t.Fatalf("completed message was not acknowledged correctly: processor=%+v, deleter=%+v", processor, deleter)
	}
}

func TestSQSMessageHandlerDefersUncompletedJobs(t *testing.T) {
	for _, disposition := range []ClaimDisposition{ClaimBusy, ClaimFailed, ClaimUnknown} {
		t.Run(string(disposition), func(t *testing.T) {
			processor := &fakeMessageProcessor{disposition: disposition}
			deleter := &fakeMessageDeleter{}
			handler, err := NewSQSMessageHandler(processor, deleter, "queue-url")
			if err != nil {
				t.Fatalf("create message handler: %v", err)
			}

			err = handler.Handle(context.Background(), testJobMessage(testUUID(17)))
			if !errors.Is(err, ErrMessageDeferred) || processor.calls != 1 || deleter.calls != 0 {
				t.Fatalf("uncompleted message was acknowledged: err=%v, processor=%+v, deleter=%+v", err, processor, deleter)
			}
		})
	}
}

func TestSQSMessageHandlerRejectsInvalidMessagesBeforeProcessing(t *testing.T) {
	validID := testUUID(17).String()
	validBody := fmt.Sprintf(`{"job_id":%q}`, validID)
	tests := []struct {
		name    string
		body    *string
		receipt *string
	}{
		{name: "missing receipt", body: aws.String(validBody)},
		{name: "empty receipt", body: aws.String(validBody), receipt: aws.String("")},
		{name: "missing body", receipt: aws.String("receipt-1")},
		{name: "invalid UUID", body: aws.String(`{"job_id":"not-a-uuid"}`), receipt: aws.String("receipt-1")},
		{name: "missing job ID", body: aws.String(`{}`), receipt: aws.String("receipt-1")},
		{name: "extra tenant field", body: aws.String(fmt.Sprintf(`{"job_id":%q,"tenant_id":"forged"}`, validID)), receipt: aws.String("receipt-1")},
		{name: "trailing JSON", body: aws.String(validBody + `{}`), receipt: aws.String("receipt-1")},
		{name: "oversized body", body: aws.String(strings.Repeat("x", 1025)), receipt: aws.String("receipt-1")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			processor := &fakeMessageProcessor{disposition: ClaimCompleted}
			deleter := &fakeMessageDeleter{}
			handler, err := NewSQSMessageHandler(processor, deleter, "queue-url")
			if err != nil {
				t.Fatalf("create message handler: %v", err)
			}
			message := sqstypes.Message{Body: test.body, ReceiptHandle: test.receipt}
			err = handler.Handle(context.Background(), message)
			if !errors.Is(err, ErrInvalidJobMessage) || processor.calls != 0 || deleter.calls != 0 {
				t.Fatalf("invalid message reached processor or deleter: err=%v, processor=%+v, deleter=%+v", err, processor, deleter)
			}
		})
	}
}

func TestSQSMessageHandlerPropagatesProcessorAndDeleteErrors(t *testing.T) {
	jobID := testUUID(17)
	processorErr := errors.New("processor unavailable")
	processor := &fakeMessageProcessor{err: processorErr}
	deleter := &fakeMessageDeleter{}
	handler, err := NewSQSMessageHandler(processor, deleter, "queue-url")
	if err != nil {
		t.Fatalf("create message handler: %v", err)
	}
	if err := handler.Handle(context.Background(), testJobMessage(jobID)); !errors.Is(err, processorErr) || deleter.calls != 0 {
		t.Fatalf("processor error was not propagated: err=%v, deleter=%+v", err, deleter)
	}

	processor.err = nil
	processor.disposition = ClaimCompleted
	deleteErr := errors.New("SQS delete unavailable")
	deleter.err = deleteErr
	if err := handler.Handle(context.Background(), testJobMessage(jobID)); !errors.Is(err, deleteErr) || deleter.calls != 1 {
		t.Fatalf("delete error was not propagated: err=%v, deleter=%+v", err, deleter)
	}
}

func TestSQSMessageHandlerRejectsInvalidConfiguration(t *testing.T) {
	processor := &fakeMessageProcessor{}
	deleter := &fakeMessageDeleter{}
	tests := []struct {
		name      string
		processor JobProcessor
		deleter   messageDeleter
		queueURL  string
	}{
		{name: "missing processor", deleter: deleter, queueURL: "queue-url"},
		{name: "missing deleter", processor: processor, queueURL: "queue-url"},
		{name: "empty queue URL", processor: processor, deleter: deleter, queueURL: " "},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSQSMessageHandler(test.processor, test.deleter, test.queueURL); !errors.Is(err, ErrInvalidProcessorConfiguration) {
				t.Fatalf("expected configuration error, got %v", err)
			}
		})
	}
}
