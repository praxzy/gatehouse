package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/praxzy/gatehouse/backend/internal/audit"
)

const requestIDHeader = "X-Request-ID"

type requestIDContextKey struct{}

func attachRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		requestID := uuid.NewString()

		writer.Header().Set(requestIDHeader, requestID)

		ctx := context.WithValue(
			request.Context(),
			requestIDContextKey{},
			requestID,
		)

		requestDetails := audit.NewRequestDetails(
			requestID,
			nil,
			request.UserAgent(),
		)

		sourceIP, err := directClientAddress(request)
		if err == nil {
			requestDetails.SourceIP = &sourceIP
		}

		ctx = audit.WithRequestDetails(
			ctx,
			requestDetails,
		)

		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}
