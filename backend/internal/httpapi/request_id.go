package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"
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

		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}
