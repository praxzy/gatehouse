package auth

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var ErrInvalidServiceConfiguration = errors.New(
	"invalid authentication service configuration",
)

type Service struct {
	pool              *pgxpool.Pool
	queries           *store.Queries
	loginRateLimiter  LoginRateLimiter
	dummyPasswordHash string
}

func NewService(
	pool *pgxpool.Pool,
	loginRateLimiter LoginRateLimiter,
) (*Service, error) {
	if pool == nil || loginRateLimiter == nil {
		return nil, ErrInvalidServiceConfiguration
	}

	dummyPasswordHash, err := HashPassword(
		"gatehouse dummy authentication password",
	)
	if err != nil {
		return nil, fmt.Errorf("create dummy password hash: %w", err)
	}

	return &Service{
		pool:              pool,
		queries:           store.New(pool),
		loginRateLimiter:  loginRateLimiter,
		dummyPasswordHash: dummyPasswordHash,
	}, nil
}
