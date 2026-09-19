package auditexport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
)

var ErrInvalidSQSWorker = errors.New("invalid SQS audit export worker configuration")

type sqsReceiver interface {
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	ChangeMessageVisibility(context.Context, *sqs.ChangeMessageVisibilityInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error)
}

type jobMessageHandler interface {
	Handle(context.Context, sqstypes.Message) error
}

type SQSWorker struct {
	receiver          sqsReceiver
	handler           jobMessageHandler
	queueURL          string
	visibilitySeconds int32
	renewInterval     time.Duration
}

func NewSQSWorker(
	receiver sqsReceiver,
	handler jobMessageHandler,
	queueURL string,
	visibilitySeconds int32,
) (*SQSWorker, error) {
	if receiver == nil || handler == nil || strings.TrimSpace(queueURL) == "" ||
		visibilitySeconds < 3 || visibilitySeconds > 43200 {
		return nil, ErrInvalidSQSWorker
	}
	return &SQSWorker{
		receiver:          receiver,
		handler:           handler,
		queueURL:          queueURL,
		visibilitySeconds: visibilitySeconds,
		renewInterval:     time.Duration(visibilitySeconds) * time.Second / 3,
	}, nil
}

// PollOnce receives one message so no other message sits idle while an export
// runs. The SQS visibility lease is renewed independently from the DB lease.
func (worker *SQSWorker) PollOnce(ctx context.Context) error {
	if worker == nil || worker.receiver == nil || worker.handler == nil {
		return ErrInvalidSQSWorker
	}
	result, err := worker.receiver.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(worker.queueURL),
		MaxNumberOfMessages: 1,
		WaitTimeSeconds:     20,
		VisibilityTimeout:   worker.visibilitySeconds,
	})
	if err != nil {
		return fmt.Errorf("receive audit export message: %w", err)
	}
	if result == nil {
		return errors.New("SQS returned no receive result")
	}
	for _, message := range result.Messages {
		if err := worker.handleOne(ctx, message); err != nil {
			return err
		}
	}
	return nil
}

func (worker *SQSWorker) handleOne(ctx context.Context, message sqstypes.Message) error {
	if message.ReceiptHandle == nil || *message.ReceiptHandle == "" {
		// Let the handler classify the malformed message; it must not process
		// or delete one without a receipt handle.
		return worker.handler.Handle(ctx, message)
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRenewal := make(chan struct{})
	renewalDone := make(chan error, 1)
	go func() {
		renewalErr := worker.renewVisibility(workCtx, message.ReceiptHandle, stopRenewal)
		if renewalErr != nil {
			cancel()
		}
		renewalDone <- renewalErr
	}()

	handleErr := worker.handler.Handle(workCtx, message)
	close(stopRenewal)
	renewalErr := <-renewalDone
	if renewalErr != nil {
		return renewalErr
	}
	return handleErr
}

func (worker *SQSWorker) renewVisibility(
	ctx context.Context,
	receiptHandle *string,
	stop <-chan struct{},
) error {
	ticker := time.NewTicker(worker.renewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_, err := worker.receiver.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
				QueueUrl:          aws.String(worker.queueURL),
				ReceiptHandle:     receiptHandle,
				VisibilityTimeout: worker.visibilitySeconds,
			})
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				return fmt.Errorf("renew audit export message visibility: %w", err)
			}
		}
	}
}

func (worker *SQSWorker) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := worker.PollOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("audit export message not completed", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

var _ sqsReceiver = (*sqs.Client)(nil)
var _ jobMessageHandler = (*SQSMessageHandler)(nil)
