package httpapi

import (
	"net/http"
)

func securityHeaders(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		headers := writer.Header()

		headers.Set(
			"Content-Security-Policy",
			"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		)
		headers.Set(
			"X-Content-Type-Options",
			"nosniff",
		)
		headers.Set(
			"X-Frame-Options",
			"DENY",
		)
		headers.Set(
			"Referrer-Policy",
			"no-referrer",
		)
		headers.Set(
			"Permissions-Policy",
			"camera=(), geolocation=(), microphone=()",
		)
		headers.Set(
			"Cross-Origin-Opener-Policy",
			"same-origin",
		)
		headers.Set(
			"X-Permitted-Cross-Domain-Policies",
			"none",
		)

		next.ServeHTTP(writer, request)
	})
}
