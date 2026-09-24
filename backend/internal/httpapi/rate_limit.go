package httpapi

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidRequestRateLimitConfig = errors.New("invalid request rate-limit configuration")
	ErrMissingRequestRateLimitKey    = errors.New("request rate-limit key is required")
)

type RequestRateLimitDecision struct {
	Allowed    bool
	RetryAfter time.Duration
}

type RequestRateLimiter interface {
	Allow(
		ctx context.Context,
		key string,
	) (RequestRateLimitDecision, error)
}

type RouteRateLimiters struct {
	MFA              *LocalRequestRateLimiter
	Authorize        *LocalRequestRateLimiter
	Token            *LocalRequestRateLimiter
	Invitations      *LocalRequestRateLimiter
	SecretManagement *LocalRequestRateLimiter
}

func NewDefaultRouteRateLimiters() (
	RouteRateLimiters,
	error,
) {
	mfa, err := NewLocalRequestRateLimiter(
		10,
		5*time.Minute,
	)
	if err != nil {
		return RouteRateLimiters{}, err
	}

	authorize, err := NewLocalRequestRateLimiter(
		60,
		time.Minute,
	)
	if err != nil {
		return RouteRateLimiters{}, err
	}

	token, err := NewLocalRequestRateLimiter(
		30,
		time.Minute,
	)
	if err != nil {
		return RouteRateLimiters{}, err
	}

	invitations, err := NewLocalRequestRateLimiter(
		20,
		time.Hour,
	)
	if err != nil {
		return RouteRateLimiters{}, err
	}

	secretManagement, err := NewLocalRequestRateLimiter(
		5,
		time.Hour,
	)
	if err != nil {
		return RouteRateLimiters{}, err
	}

	return RouteRateLimiters{
		MFA:              mfa,
		Authorize:        authorize,
		Token:            token,
		Invitations:      invitations,
		SecretManagement: secretManagement,
	}, nil
}

type requestRateLimitWindow struct {
	requests int
	resetAt  time.Time
}

type LocalRequestRateLimiter struct {
	mu sync.Mutex

	maxRequests int
	window      time.Duration
	requests    map[string]requestRateLimitWindow

	now       func() time.Time
	nextSweep time.Time
}

func NewLocalRequestRateLimiter(
	maxRequests int,
	window time.Duration,
) (*LocalRequestRateLimiter, error) {
	if maxRequests <= 0 || window <= 0 {
		return nil, ErrInvalidRequestRateLimitConfig
	}

	now := time.Now()

	return &LocalRequestRateLimiter{
		maxRequests: maxRequests,
		window:      window,
		requests:    make(map[string]requestRateLimitWindow),
		now:         time.Now,
		nextSweep:   now.Add(window),
	}, nil
}

func (limiter *LocalRequestRateLimiter) Allow(
	ctx context.Context,
	key string,
) (RequestRateLimitDecision, error) {
	if err := ctx.Err(); err != nil {
		return RequestRateLimitDecision{}, err
	}

	key = strings.TrimSpace(key)
	if key == "" {
		return RequestRateLimitDecision{},
			ErrMissingRequestRateLimitKey
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	limiter.sweepExpiredEntries(now)

	current, exists := limiter.requests[key]
	if !exists || !now.Before(current.resetAt) {
		current = requestRateLimitWindow{
			resetAt: now.Add(limiter.window),
		}
	}

	if current.requests >= limiter.maxRequests {
		return RequestRateLimitDecision{
			Allowed:    false,
			RetryAfter: current.resetAt.Sub(now),
		}, nil
	}

	current.requests++
	limiter.requests[key] = current

	return RequestRateLimitDecision{
		Allowed: true,
	}, nil
}

func (limiter *LocalRequestRateLimiter) Middleware(
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		clientIP, err := directClientIP(request)
		if err != nil {
			writeError(
				writer,
				http.StatusInternalServerError,
				"internal server error",
			)
			return
		}

		decision, err := limiter.Allow(
			request.Context(),
			"ip:"+clientIP,
		)
		if err != nil {
			writeError(
				writer,
				http.StatusInternalServerError,
				"internal server error",
			)
			return
		}

		if !decision.Allowed {
			retryAfter := int(math.Ceil(
				decision.RetryAfter.Seconds(),
			))
			if retryAfter < 1 {
				retryAfter = 1
			}

			writer.Header().Set(
				"Retry-After",
				strconv.Itoa(retryAfter),
			)
			writeError(
				writer,
				http.StatusTooManyRequests,
				"too many requests",
			)
			return
		}

		next.ServeHTTP(writer, request)
	})
}

func (limiter *LocalRequestRateLimiter) sweepExpiredEntries(
	now time.Time,
) {
	if now.Before(limiter.nextSweep) {
		return
	}

	for key, window := range limiter.requests {
		if !now.Before(window.resetAt) {
			delete(limiter.requests, key)
		}
	}

	limiter.nextSweep = now.Add(limiter.window)
}

func optionalRequestRateLimit(
	limiter *LocalRequestRateLimiter,
) func(http.Handler) http.Handler {
	if limiter == nil {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return limiter.Middleware
}
