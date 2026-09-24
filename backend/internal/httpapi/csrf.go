package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const csrfHeaderName = "X-CSRF-Token"

var (
	ErrInvalidCSRFConfiguration = errors.New(
		"invalid CSRF configuration",
	)
	ErrInvalidCSRFSession = errors.New(
		"invalid CSRF session",
	)
)

type CSRFProtector struct {
	key            []byte
	allowedOrigins map[string]struct{}
}

func NewCSRFProtector(
	key []byte,
	allowedOrigins []string,
) (*CSRFProtector, error) {
	if len(key) < 32 || len(allowedOrigins) == 0 {
		return nil, ErrInvalidCSRFConfiguration
	}

	origins := make(
		map[string]struct{},
		len(allowedOrigins),
	)

	for _, value := range allowedOrigins {
		origin, err := canonicalOrigin(
			value,
			false,
		)
		if err != nil {
			return nil, ErrInvalidCSRFConfiguration
		}

		origins[origin] = struct{}{}
	}

	keyCopy := append([]byte(nil), key...)

	return &CSRFProtector{
		key:            keyCopy,
		allowedOrigins: origins,
	}, nil
}

func (protector *CSRFProtector) Token(
	sessionToken string,
) (string, error) {
	if sessionToken == "" {
		return "", ErrInvalidCSRFSession
	}

	mac := hmac.New(
		sha256.New,
		protector.key,
	)

	_, _ = mac.Write(
		[]byte("gatehouse-csrf-v1\x00"),
	)
	_, _ = mac.Write(
		[]byte(sessionToken),
	)

	return base64.RawURLEncoding.EncodeToString(
		mac.Sum(nil),
	), nil
}

func (protector *CSRFProtector) Protect(
	sessionCookie SessionCookie,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			if isSafeMethod(request.Method) {
				next.ServeHTTP(writer, request)
				return
			}

			if !protector.originAllowed(request) {
				writeError(
					writer,
					http.StatusForbidden,
					"request could not be verified",
				)
				return
			}

			sessionToken, err :=
				sessionCookie.Read(request)
			if err != nil {
				writeError(
					writer,
					http.StatusForbidden,
					"request could not be verified",
				)
				return
			}

			expectedToken, err :=
				protector.Token(sessionToken)
			if err != nil {
				writeError(
					writer,
					http.StatusForbidden,
					"request could not be verified",
				)
				return
			}

			values := request.Header.Values(
				csrfHeaderName,
			)
			if len(values) != 1 {
				writeError(
					writer,
					http.StatusForbidden,
					"request could not be verified",
				)
				return
			}

			providedToken := values[0]

			if len(providedToken) !=
				len(expectedToken) ||
				subtle.ConstantTimeCompare(
					[]byte(providedToken),
					[]byte(expectedToken),
				) != 1 {
				writeError(
					writer,
					http.StatusForbidden,
					"request could not be verified",
				)
				return
			}

			next.ServeHTTP(writer, request)
		})
	}
}

func (protector *CSRFProtector) originAllowed(
	request *http.Request,
) bool {
	origin, err := requestSourceOrigin(
		request,
	)
	if err != nil {
		return false
	}

	_, allowed :=
		protector.allowedOrigins[origin]

	return allowed
}

func requestSourceOrigin(
	request *http.Request,
) (string, error) {
	origin := strings.TrimSpace(
		request.Header.Get("Origin"),
	)
	if origin != "" {
		return canonicalOrigin(
			origin,
			false,
		)
	}

	referer := strings.TrimSpace(
		request.Header.Get("Referer"),
	)
	if referer == "" {
		return "", ErrInvalidCSRFConfiguration
	}

	return canonicalOrigin(
		referer,
		true,
	)
}

func canonicalOrigin(
	value string,
	allowPath bool,
) (string, error) {
	parsed, err := url.Parse(
		strings.TrimSpace(value),
	)
	if err != nil {
		return "", err
	}

	scheme := strings.ToLower(
		parsed.Scheme,
	)
	if scheme != "http" &&
		scheme != "https" {
		return "", ErrInvalidCSRFConfiguration
	}

	if parsed.Hostname() == "" ||
		parsed.User != nil {
		return "", ErrInvalidCSRFConfiguration
	}

	if !allowPath &&
		(parsed.Path != "" &&
			parsed.Path != "/" ||
			parsed.RawQuery != "" ||
			parsed.Fragment != "") {
		return "", ErrInvalidCSRFConfiguration
	}

	return scheme +
		"://" +
		strings.ToLower(parsed.Host), nil
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet,
		http.MethodHead,
		http.MethodOptions:
		return true
	default:
		return false
	}
}

func (protector *CSRFProtector) ProtectOrigin(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		if isSafeMethod(request.Method) {
			next.ServeHTTP(writer, request)
			return
		}

		if !protector.originAllowed(request) {
			writeError(
				writer,
				http.StatusForbidden,
				"request could not be verified",
			)
			return
		}

		next.ServeHTTP(writer, request)
	})
}
