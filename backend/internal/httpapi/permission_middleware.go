package httpapi

import (
	"net/http"
)

func requirePermission(
	permission string,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			session, ok := sessionFromContext(
				request.Context(),
			)
			if !ok {
				writeError(
					writer,
					http.StatusUnauthorized,
					"authentication required",
				)
				return
			}

			if !session.HasPermission(permission) {
				writeError(
					writer,
					http.StatusForbidden,
					"permission denied",
				)
				return
			}

			next.ServeHTTP(writer, request)
		})
	}
}
