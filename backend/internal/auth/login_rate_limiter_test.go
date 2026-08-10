package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLocalLoginRateLimiterBlocksAfterLimit(t *testing.T) {
	limiter, err := NewLocalLoginRateLimiter(3, 10*time.Minute)
	if err != nil {
		t.Fatalf("create limiter: %v", err)
	}

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time {
		return now
	}

	for attempt := 1; attempt <= 3; attempt++ {
		decision, err := limiter.Allow(
			context.Background(),
			"account:alice",
		)
		if err != nil {
			t.Fatalf("allow attempt %d: %v", attempt, err)
		}

		if !decision.Allowed {
			t.Fatalf("expected attempt %d to be allowed", attempt)
		}
	}

	decision, err := limiter.Allow(
		context.Background(),
		"account:alice",
	)
	if err != nil {
		t.Fatalf("check blocked attempt: %v", err)
	}

	if decision.Allowed {
		t.Fatal("expected fourth attempt to be blocked")
	}

	if decision.RetryAfter != 10*time.Minute {
		t.Fatalf(
			"expected ten-minute retry, got %v",
			decision.RetryAfter,
		)
	}
}

func TestLocalLoginRateLimiterResetsAfterWindow(t *testing.T) {
	limiter, err := NewLocalLoginRateLimiter(1, 5*time.Minute)
	if err != nil {
		t.Fatalf("create limiter: %v", err)
	}

	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time {
		return now
	}

	first, err := limiter.Allow(context.Background(), "ip:127.0.0.1")
	if err != nil {
		t.Fatalf("allow first attempt: %v", err)
	}

	if !first.Allowed {
		t.Fatal("expected first attempt to be allowed")
	}

	now = now.Add(5 * time.Minute)

	afterReset, err := limiter.Allow(
		context.Background(),
		"ip:127.0.0.1",
	)
	if err != nil {
		t.Fatalf("allow attempt after reset: %v", err)
	}

	if !afterReset.Allowed {
		t.Fatal("expected attempt after window to be allowed")
	}
}

func TestLocalLoginRateLimiterChecksAllKeys(t *testing.T) {
	limiter, err := NewLocalLoginRateLimiter(1, 10*time.Minute)
	if err != nil {
		t.Fatalf("create limiter: %v", err)
	}

	_, err = limiter.Allow(
		context.Background(),
		"account:alice",
	)
	if err != nil {
		t.Fatalf("consume account limit: %v", err)
	}

	decision, err := limiter.Allow(
		context.Background(),
		"ip:127.0.0.1",
		"account:alice",
	)
	if err != nil {
		t.Fatalf("check combined keys: %v", err)
	}

	if decision.Allowed {
		t.Fatal("expected blocked account key to reject login")
	}
}

func TestLocalLoginRateLimiterDoesNotDoubleCountDuplicateKeys(
	t *testing.T,
) {
	limiter, err := NewLocalLoginRateLimiter(2, 10*time.Minute)
	if err != nil {
		t.Fatalf("create limiter: %v", err)
	}

	first, err := limiter.Allow(
		context.Background(),
		"account:alice",
		"account:alice",
	)
	if err != nil {
		t.Fatalf("allow duplicated key: %v", err)
	}

	if !first.Allowed {
		t.Fatal("expected first attempt to be allowed")
	}

	second, err := limiter.Allow(
		context.Background(),
		"account:alice",
	)
	if err != nil {
		t.Fatalf("allow second attempt: %v", err)
	}

	if !second.Allowed {
		t.Fatal("duplicate key should have counted only once")
	}
}

func TestLocalLoginRateLimiterValidatesInput(t *testing.T) {
	_, err := NewLocalLoginRateLimiter(0, time.Minute)
	if !errors.Is(err, ErrInvalidRateLimitConfig) {
		t.Fatalf(
			"expected ErrInvalidRateLimitConfig, got %v",
			err,
		)
	}

	limiter, err := NewLocalLoginRateLimiter(5, time.Minute)
	if err != nil {
		t.Fatalf("create limiter: %v", err)
	}

	_, err = limiter.Allow(context.Background())
	if !errors.Is(err, ErrMissingRateLimitKey) {
		t.Fatalf("expected ErrMissingRateLimitKey, got %v", err)
	}
}
