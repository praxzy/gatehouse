package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLocalRequestRateLimiterBlocksAndResets(
	t *testing.T,
) {
	limiter, err := NewLocalRequestRateLimiter(
		2,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("create rate limiter: %v", err)
	}

	now := time.Date(
		2026,
		time.September,
		24,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	limiter.now = func() time.Time {
		return now
	}
	limiter.nextSweep = now.Add(time.Minute)

	handlerCalls := 0
	handler := limiter.Middleware(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			handlerCalls++
			writer.WriteHeader(http.StatusNoContent)
		}),
	)

	for attempt := 0; attempt < 2; attempt++ {
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/auth/mfa/challenge/totp",
			nil,
		)
		request.RemoteAddr = "192.0.2.10:1234"

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if response.Code != http.StatusNoContent {
			t.Fatalf(
				"attempt %d: expected status %d, got %d",
				attempt+1,
				http.StatusNoContent,
				response.Code,
			)
		}
	}

	blockedRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/mfa/challenge/totp",
		nil,
	)
	blockedRequest.RemoteAddr = "192.0.2.10:1234"

	blockedResponse := httptest.NewRecorder()
	handler.ServeHTTP(
		blockedResponse,
		blockedRequest,
	)

	if blockedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusTooManyRequests,
			blockedResponse.Code,
		)
	}

	if blockedResponse.Header().Get("Retry-After") != "60" {
		t.Fatalf(
			"expected Retry-After 60, got %q",
			blockedResponse.Header().Get("Retry-After"),
		)
	}

	if handlerCalls != 2 {
		t.Fatalf(
			"blocked request reached handler; calls = %d",
			handlerCalls,
		)
	}

	now = now.Add(time.Minute)

	resetRequest := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/mfa/challenge/totp",
		nil,
	)
	resetRequest.RemoteAddr = "192.0.2.10:1234"

	resetResponse := httptest.NewRecorder()
	handler.ServeHTTP(resetResponse, resetRequest)

	if resetResponse.Code != http.StatusNoContent {
		t.Fatalf(
			"expected request after reset to succeed, got %d",
			resetResponse.Code,
		)
	}
}

func TestLocalRequestRateLimiterSeparatesClients(
	t *testing.T,
) {
	limiter, err := NewLocalRequestRateLimiter(
		1,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("create rate limiter: %v", err)
	}

	handler := limiter.Middleware(
		http.HandlerFunc(func(
			writer http.ResponseWriter,
			_ *http.Request,
		) {
			writer.WriteHeader(http.StatusNoContent)
		}),
	)

	for _, remoteAddress := range []string{
		"192.0.2.10:1234",
		"192.0.2.11:1234",
	} {
		request := httptest.NewRequest(
			http.MethodPost,
			"/oauth/token",
			nil,
		)
		request.RemoteAddr = remoteAddress

		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		if response.Code != http.StatusNoContent {
			t.Fatalf(
				"client %s received status %d",
				remoteAddress,
				response.Code,
			)
		}
	}
}

func TestLocalRequestRateLimiterValidatesInput(
	t *testing.T,
) {
	if _, err := NewLocalRequestRateLimiter(
		0,
		time.Minute,
	); err == nil {
		t.Fatal("expected invalid configuration error")
	}

	limiter, err := NewLocalRequestRateLimiter(
		1,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("create rate limiter: %v", err)
	}

	if _, err := limiter.Allow(
		context.Background(),
		" ",
	); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestRouterRateLimitsTokenEndpoint(
	t *testing.T,
) {
	limiter, err := NewLocalRequestRateLimiter(
		1,
		time.Minute,
	)
	if err != nil {
		t.Fatalf("create rate limiter: %v", err)
	}

	service := &stubOIDCTokenService{}

	router := NewRouter(Dependencies{
		OIDCTokens: service,
		RateLimiters: RouteRateLimiters{
			Token: limiter,
		},
	})

	firstRequest := newTokenEndpointRequest(
		validTokenEndpointForm(),
	)
	firstRequest.RemoteAddr = "192.0.2.10:1234"

	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, firstRequest)

	if firstResponse.Code != http.StatusOK {
		t.Fatalf(
			"expected first request status %d, got %d",
			http.StatusOK,
			firstResponse.Code,
		)
	}

	if !service.called {
		t.Fatal("first request did not reach token service")
	}

	service.called = false

	secondRequest := newTokenEndpointRequest(
		validTokenEndpointForm(),
	)
	secondRequest.RemoteAddr = "192.0.2.10:4321"

	secondResponse := httptest.NewRecorder()
	router.ServeHTTP(secondResponse, secondRequest)

	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf(
			"expected second request status %d, got %d",
			http.StatusTooManyRequests,
			secondResponse.Code,
		)
	}

	if secondResponse.Header().Get("Retry-After") == "" {
		t.Fatal("rate-limited response omitted Retry-After")
	}

	if service.called {
		t.Fatal("rate-limited request reached token service")
	}
}

func TestDefaultRouteRateLimitersCoverPublicResourceWork(
	t *testing.T,
) {
	limiters, err := NewDefaultRouteRateLimiters()
	if err != nil {
		t.Fatalf("create default route limiters: %v", err)
	}

	if limiters.Registration == nil {
		t.Fatal("registration rate limiter is not configured")
	}
	if limiters.Federation == nil {
		t.Fatal("federation rate limiter is not configured")
	}
}
