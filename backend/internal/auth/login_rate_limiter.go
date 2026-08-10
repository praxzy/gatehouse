package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidRateLimitConfig = errors.New("invalid login rate-limit configuration")
	ErrMissingRateLimitKey    = errors.New("login rate-limit key is required")
)

type LoginRateLimitDecision struct {
	Allowed    bool
	RetryAfter time.Duration
}

type LoginRateLimiter interface {
	Allow(
		ctx context.Context,
		keys ...string,
	) (LoginRateLimitDecision, error)
}

type loginAttemptWindow struct {
	attempts int
	resetAt  time.Time
}

type LocalLoginRateLimiter struct {
	mu sync.Mutex

	maxAttempts int
	window      time.Duration
	attempts    map[string]loginAttemptWindow

	now       func() time.Time
	nextSweep time.Time
}

func NewLocalLoginRateLimiter(
	maxAttempts int,
	window time.Duration,
) (*LocalLoginRateLimiter, error) {
	if maxAttempts <= 0 || window <= 0 {
		return nil, ErrInvalidRateLimitConfig
	}

	now := time.Now()

	return &LocalLoginRateLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		attempts:    make(map[string]loginAttemptWindow),
		now:         time.Now,
		nextSweep:   now.Add(window),
	}, nil
}

func (limiter *LocalLoginRateLimiter) Allow(
	ctx context.Context,
	keys ...string,
) (LoginRateLimitDecision, error) {
	if err := ctx.Err(); err != nil {
		return LoginRateLimitDecision{}, err
	}

	uniqueKeys, err := uniqueRateLimitKeys(keys)
	if err != nil {
		return LoginRateLimitDecision{}, err
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	limiter.sweepExpiredEntries(now)

	currentWindows := make(
		map[string]loginAttemptWindow,
		len(uniqueKeys),
	)

	var retryAfter time.Duration

	for _, key := range uniqueKeys {
		window, exists := limiter.attempts[key]

		if !exists || !now.Before(window.resetAt) {
			window = loginAttemptWindow{
				resetAt: now.Add(limiter.window),
			}
		}

		currentWindows[key] = window

		if window.attempts >= limiter.maxAttempts {
			keyRetryAfter := window.resetAt.Sub(now)
			if keyRetryAfter > retryAfter {
				retryAfter = keyRetryAfter
			}
		}
	}

	if retryAfter > 0 {
		return LoginRateLimitDecision{
			Allowed:    false,
			RetryAfter: retryAfter,
		}, nil
	}

	for key, window := range currentWindows {
		window.attempts++
		limiter.attempts[key] = window
	}

	return LoginRateLimitDecision{
		Allowed: true,
	}, nil
}

func (limiter *LocalLoginRateLimiter) sweepExpiredEntries(now time.Time) {
	if now.Before(limiter.nextSweep) {
		return
	}

	for key, window := range limiter.attempts {
		if !now.Before(window.resetAt) {
			delete(limiter.attempts, key)
		}
	}

	limiter.nextSweep = now.Add(limiter.window)
}

func uniqueRateLimitKeys(keys []string) ([]string, error) {
	seen := make(map[string]struct{}, len(keys))
	unique := make([]string, 0, len(keys))

	for _, key := range keys {
		if key == "" {
			return nil, ErrMissingRateLimitKey
		}

		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		unique = append(unique, key)
	}

	if len(unique) == 0 {
		return nil, ErrMissingRateLimitKey
	}

	return unique, nil
}
