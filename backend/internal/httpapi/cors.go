package httpapi

import (
	"net/http"
	"strings"
)

const (
	corsAllowedMethods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
	corsAllowedHeaders = "Accept, Content-Type, X-CSRF-Token"
)

var allowedCORSMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodPost:    {},
	http.MethodPut:     {},
	http.MethodPatch:   {},
	http.MethodDelete:  {},
	http.MethodOptions: {},
}

var allowedCORSHeaders = map[string]struct{}{
	"accept":       {},
	"content-type": {},
	"x-csrf-token": {},
}

func (protector *CSRFProtector) CORS(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		originValues := request.Header.Values(
			"Origin",
		)
		if len(originValues) == 0 {
			next.ServeHTTP(writer, request)
			return
		}

		if len(originValues) != 1 {
			writeError(
				writer,
				http.StatusForbidden,
				"origin is not allowed",
			)
			return
		}

		origin, err := canonicalOrigin(
			originValues[0],
			false,
		)
		if err != nil {
			writeError(
				writer,
				http.StatusForbidden,
				"origin is not allowed",
			)
			return
		}

		if _, allowed := protector.allowedOrigins[origin]; !allowed {
			writeError(
				writer,
				http.StatusForbidden,
				"origin is not allowed",
			)
			return
		}

		headers := writer.Header()
		headers.Add("Vary", "Origin")
		headers.Set(
			"Access-Control-Allow-Origin",
			origin,
		)
		headers.Set(
			"Access-Control-Allow-Credentials",
			"true",
		)
		headers.Set(
			"Access-Control-Expose-Headers",
			"X-Request-ID",
		)

		if !isCORSPreflight(request) {
			next.ServeHTTP(writer, request)
			return
		}

		headers.Add(
			"Vary",
			"Access-Control-Request-Method",
		)
		headers.Add(
			"Vary",
			"Access-Control-Request-Headers",
		)

		requestedMethod := strings.ToUpper(
			strings.TrimSpace(
				request.Header.Get(
					"Access-Control-Request-Method",
				),
			),
		)
		if _, allowed := allowedCORSMethods[requestedMethod]; !allowed {
			writeError(
				writer,
				http.StatusForbidden,
				"CORS preflight is not allowed",
			)
			return
		}

		if !corsRequestHeadersAllowed(
			request.Header.Get(
				"Access-Control-Request-Headers",
			),
		) {
			writeError(
				writer,
				http.StatusForbidden,
				"CORS preflight is not allowed",
			)
			return
		}

		headers.Set(
			"Access-Control-Allow-Methods",
			corsAllowedMethods,
		)
		headers.Set(
			"Access-Control-Allow-Headers",
			corsAllowedHeaders,
		)
		headers.Set(
			"Access-Control-Max-Age",
			"600",
		)
		writer.WriteHeader(http.StatusNoContent)
	})
}

func isCORSPreflight(
	request *http.Request,
) bool {
	return request.Method == http.MethodOptions &&
		strings.TrimSpace(
			request.Header.Get(
				"Access-Control-Request-Method",
			),
		) != ""
}

func corsRequestHeadersAllowed(
	value string,
) bool {
	for _, rawHeader := range strings.Split(
		value,
		",",
	) {
		header := strings.ToLower(
			strings.TrimSpace(rawHeader),
		)
		if header == "" {
			continue
		}

		if _, allowed := allowedCORSHeaders[header]; !allowed {
			return false
		}
	}

	return true
}
