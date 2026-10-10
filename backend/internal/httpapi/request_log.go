package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

type requestLogContextKey struct{}

type requestLogIdentity struct {
	mu            sync.RWMutex
	tenantID      string
	userID        string
	applicationID string
}

type responseMetricsWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			startedAt := time.Now()
			identity := &requestLogIdentity{}

			ctx := context.WithValue(
				request.Context(),
				requestLogContextKey{},
				identity,
			)

			metricsWriter := &responseMetricsWriter{
				ResponseWriter: writer,
				status:         http.StatusOK,
			}

			next.ServeHTTP(
				metricsWriter,
				request.WithContext(ctx),
			)

			route := chi.RouteContext(ctx).RoutePattern()
			if route == "" {
				route = "unmatched"
			}

			if route == "/healthz" &&
				metricsWriter.status < http.StatusBadRequest {
				return
			}

			logRequestCompletion(
				ctx,
				logger,
				request.Method,
				route,
				metricsWriter,
				time.Since(startedAt),
				identity,
			)
		})
	}
}

func (writer *responseMetricsWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}

	writer.status = status
	writer.wroteHeader = true
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseMetricsWriter) Write(value []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}

	written, err := writer.ResponseWriter.Write(value)
	writer.bytes += written
	return written, err
}

func (writer *responseMetricsWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func setRequestLogIdentity(
	ctx context.Context,
	tenantID string,
	userID string,
	applicationID string,
) {
	identity, ok := ctx.Value(
		requestLogContextKey{},
	).(*requestLogIdentity)
	if !ok {
		return
	}

	identity.mu.Lock()
	defer identity.mu.Unlock()

	if tenantID != "" {
		identity.tenantID = tenantID
	}
	if userID != "" {
		identity.userID = userID
	}
	if applicationID != "" {
		identity.applicationID = applicationID
	}
}

func logRequestCompletion(
	ctx context.Context,
	logger *slog.Logger,
	method string,
	route string,
	writer *responseMetricsWriter,
	duration time.Duration,
	identity *requestLogIdentity,
) {
	attributes := []slog.Attr{
		slog.String("request_id", requestIDFromContext(ctx)),
		slog.String("method", method),
		slog.String("route", route),
		slog.Int("status", writer.status),
		slog.Int("response_bytes", writer.bytes),
		slog.Int64("duration_ms", duration.Milliseconds()),
	}

	identity.mu.RLock()
	if identity.tenantID != "" {
		attributes = append(
			attributes,
			slog.String("tenant_id", identity.tenantID),
		)
	}
	if identity.userID != "" {
		attributes = append(
			attributes,
			slog.String("user_id", identity.userID),
		)
	}
	if identity.applicationID != "" {
		attributes = append(
			attributes,
			slog.String(
				"application_id",
				identity.applicationID,
			),
		)
	}
	identity.mu.RUnlock()

	level := slog.LevelInfo
	if writer.status >= http.StatusInternalServerError {
		level = slog.LevelError
	} else if writer.status == http.StatusTooManyRequests {
		level = slog.LevelWarn
	}

	logger.LogAttrs(
		ctx,
		level,
		"HTTP request completed",
		attributes...,
	)
}
