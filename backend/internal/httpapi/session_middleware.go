package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/praxzy/gatehouse/backend/internal/auth"
)

type sessionContextKey struct{}

func requireSession(
	authentication AuthenticationService,
	sessionCookie SessionCookie,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			rawToken, err := sessionCookie.Read(request)
			if err != nil {
				writeError(
					writer,
					http.StatusUnauthorized,
					"authentication required",
				)
				return
			}

			session, err := authentication.ResolveSession(
				request.Context(),
				rawToken,
			)
			if errors.Is(err, auth.ErrInvalidSession) {
				sessionCookie.Clear(writer)
				writeError(
					writer,
					http.StatusUnauthorized,
					"authentication required",
				)
				return
			}
			if err != nil {
				writeError(
					writer,
					http.StatusInternalServerError,
					"internal server error",
				)
				return
			}

			ctx := context.WithValue(
				request.Context(),
				sessionContextKey{},
				session,
			)

			next.ServeHTTP(
				writer,
				request.WithContext(ctx),
			)
		})
	}
}

func sessionFromContext(
	ctx context.Context,
) (auth.SessionContext, bool) {
	session, ok := ctx.Value(sessionContextKey{}).(auth.SessionContext)
	return session, ok
}
