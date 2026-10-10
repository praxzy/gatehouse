package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/auditexport"
	"github.com/praxzy/gatehouse/backend/internal/observability"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const (
	databaseLeaseSeconds int32 = 60
	sqsVisibilitySeconds int32 = 90
)

func main() {
	slog.SetDefault(observability.NewJSONLogger(os.Stdout))

	if err := run(); err != nil {
		slog.Error("audit export worker stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	queueURL := strings.TrimSpace(os.Getenv("AUDIT_EXPORT_QUEUE_URL"))
	bucket := strings.TrimSpace(os.Getenv("AUDIT_EXPORT_BUCKET"))
	if databaseURL == "" || queueURL == "" || bucket == "" {
		return errors.New("DATABASE_URL, AUDIT_EXPORT_QUEUE_URL, and AUDIT_EXPORT_BUCKET are required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("open database pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	if awsConfig.Region == "" {
		return errors.New("AWS_REGION is required")
	}

	queries := store.New(pool)
	renderer, err := auditexport.NewRenderer(queries)
	if err != nil {
		return err
	}
	objects, err := auditexport.NewS3ObjectStore(
		transfermanager.New(s3.NewFromConfig(awsConfig)), bucket,
	)
	if err != nil {
		return err
	}
	processor, err := auditexport.NewProcessor(queries, renderer, objects, databaseLeaseSeconds)
	if err != nil {
		return err
	}
	sqsClient := sqs.NewFromConfig(awsConfig)
	handler, err := auditexport.NewSQSMessageHandler(processor, sqsClient, queueURL)
	if err != nil {
		return err
	}
	worker, err := auditexport.NewSQSWorker(sqsClient, handler, queueURL, sqsVisibilitySeconds)
	if err != nil {
		return err
	}

	go reconcileExpiredJobs(ctx, processor)
	slog.Info("audit export worker started")
	worker.Run(ctx)
	return nil
}

func reconcileExpiredJobs(ctx context.Context, processor *auditexport.Processor) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		count, err := processor.ReconcileExhausted(attemptCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("reconcile exhausted audit exports", "error", err)
		} else if count > 0 {
			slog.Info("failed exhausted audit exports", "count", count)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
