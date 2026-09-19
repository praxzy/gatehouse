package auditexport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

type fakeSQSReceiver struct {
	receiveInput  *sqs.ReceiveMessageInput
	receiveOutput *sqs.ReceiveMessageOutput
	receiveErr    error
	changeInput   *sqs.ChangeMessageVisibilityInput
	changeErr     error
	changeCalls   int
	changed       chan struct{}
}

func (fake *fakeSQSReceiver) ReceiveMessage(
	_ context.Context,
	input *sqs.ReceiveMessageInput,
	_ ...func(*sqs.Options),
) (*sqs.ReceiveMessageOutput, error) {
	fake.receiveInput = input
	return fake.receiveOutput, fake.receiveErr
}

func (fake *fakeSQSReceiver) ChangeMessageVisibility(
	_ context.Context,
	input *sqs.ChangeMessageVisibilityInput,
	_ ...func(*sqs.Options),
) (*sqs.ChangeMessageVisibilityOutput, error) {
	fake.changeInput = input
	fake.changeCalls++
	if fake.changed != nil && fake.changeCalls == 1 {
		close(fake.changed)
	}
	if fake.changeErr != nil {
		return nil, fake.changeErr
	}
	return &sqs.ChangeMessageVisibilityOutput{}, nil
}

type messageHandlerFunc func(context.Context, sqstypes.Message) error

func (handle messageHandlerFunc) Handle(ctx context.Context, message sqstypes.Message) error {
	return handle(ctx, message)
}

func TestSQSWorkerReceivesOneMessageAtATime(t *testing.T) {
	message := testJobMessage(testUUID(17))
	receiver := &fakeSQSReceiver{receiveOutput: &sqs.ReceiveMessageOutput{
		Messages: []sqstypes.Message{message},
	}}
	called := 0
	worker, err := NewSQSWorker(receiver, messageHandlerFunc(func(_ context.Context, received sqstypes.Message) error {
		called++
		if aws.ToString(received.Body) != aws.ToString(message.Body) {
			return errors.New("wrong message body")
		}
		return nil
	}), "queue-url", 90)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}
	if err := worker.PollOnce(context.Background()); err != nil {
		t.Fatalf("poll SQS: %v", err)
	}
	if called != 1 || receiver.receiveInput == nil ||
		aws.ToString(receiver.receiveInput.QueueUrl) != "queue-url" ||
		receiver.receiveInput.MaxNumberOfMessages != 1 ||
		receiver.receiveInput.WaitTimeSeconds != 20 ||
		receiver.receiveInput.VisibilityTimeout != 90 || receiver.changeCalls != 0 {
		t.Fatalf("unexpected receive behavior: calls=%d, receiver=%+v", called, receiver)
	}
}

func TestSQSWorkerRenewsMessageVisibilityDuringProcessing(t *testing.T) {
	message := testJobMessage(testUUID(17))
	renewed := make(chan struct{})
	receiver := &fakeSQSReceiver{
		receiveOutput: &sqs.ReceiveMessageOutput{Messages: []sqstypes.Message{message}},
		changed:       renewed,
	}
	worker, err := NewSQSWorker(receiver, messageHandlerFunc(func(ctx context.Context, _ sqstypes.Message) error {
		select {
		case <-renewed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}), "queue-url", 90)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}
	worker.renewInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.PollOnce(ctx); err != nil {
		t.Fatalf("poll SQS: %v", err)
	}
	if receiver.changeCalls < 1 || receiver.changeInput == nil ||
		aws.ToString(receiver.changeInput.QueueUrl) != "queue-url" ||
		aws.ToString(receiver.changeInput.ReceiptHandle) != "receipt-1" ||
		receiver.changeInput.VisibilityTimeout != 90 {
		t.Fatalf("message visibility was not renewed: %+v", receiver)
	}
}

func TestSQSWorkerCancelsProcessingWhenVisibilityRenewalFails(t *testing.T) {
	renewErr := errors.New("SQS visibility unavailable")
	receiver := &fakeSQSReceiver{
		receiveOutput: &sqs.ReceiveMessageOutput{
			Messages: []sqstypes.Message{testJobMessage(testUUID(17))},
		},
		changeErr: renewErr,
	}
	worker, err := NewSQSWorker(receiver, messageHandlerFunc(func(ctx context.Context, _ sqstypes.Message) error {
		<-ctx.Done()
		return ctx.Err()
	}), "queue-url", 90)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}
	worker.renewInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := worker.PollOnce(ctx); !errors.Is(err, renewErr) {
		t.Fatalf("expected renewal error, got %v", err)
	}
}

func TestSQSWorkerDoesNotProcessEmptyReceive(t *testing.T) {
	receiver := &fakeSQSReceiver{receiveOutput: &sqs.ReceiveMessageOutput{}}
	worker, err := NewSQSWorker(receiver, messageHandlerFunc(func(context.Context, sqstypes.Message) error {
		t.Fatal("empty receive reached handler")
		return nil
	}), "queue-url", 90)
	if err != nil {
		t.Fatalf("create worker: %v", err)
	}
	if err := worker.PollOnce(context.Background()); err != nil {
		t.Fatalf("empty receive should succeed: %v", err)
	}
}

func TestSQSWorkerRejectsInvalidConfiguration(t *testing.T) {
	receiver := &fakeSQSReceiver{}
	handler := messageHandlerFunc(func(context.Context, sqstypes.Message) error { return nil })
	for _, test := range []struct {
		name       string
		receiver   sqsReceiver
		handler    jobMessageHandler
		queueURL   string
		visibility int32
	}{
		{name: "missing receiver", handler: handler, queueURL: "queue-url", visibility: 90},
		{name: "missing handler", receiver: receiver, queueURL: "queue-url", visibility: 90},
		{name: "missing queue URL", receiver: receiver, handler: handler, visibility: 90},
		{name: "invalid visibility", receiver: receiver, handler: handler, queueURL: "queue-url", visibility: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSQSWorker(test.receiver, test.handler, test.queueURL, test.visibility); !errors.Is(err, ErrInvalidSQSWorker) {
				t.Fatalf("expected worker configuration error, got %v", err)
			}
		})
	}
}
