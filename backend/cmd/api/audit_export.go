package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auditexport"
)

func auditExportServiceFromEnvironment(
	ctx context.Context,
	pool *pgxpool.Pool,
	writer audit.EventWriter,
) (*auditexport.Service, error) {
	queueURL := strings.TrimSpace(os.Getenv("AUDIT_EXPORT_QUEUE_URL"))
	if queueURL == "" {
		return nil, nil
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("AWS_REGION is required for audit exports")
	}

	publisher, err := auditexport.NewSQSPublisher(
		sqs.NewFromConfig(cfg),
		queueURL,
	)
	if err != nil {
		return nil, err
	}
	return auditexport.NewService(pool, writer, publisher)
}

func runAuditExportDispatcher(
	ctx context.Context,
	service *auditexport.Service,
) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		attemptCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := service.DispatchPending(attemptCtx, 50)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("retry pending audit exports", "error", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}