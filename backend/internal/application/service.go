package application

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type ClientType string

const (
	ClientTypePublic       ClientType = "public"
	ClientTypeConfidential ClientType = "confidential"
)

type AccessMode string

const (
	AccessModeAllActiveMembers AccessMode = "all_active_members"
	AccessModeAllowedRoles     AccessMode = "allowed_roles"
)

var (
	ErrInvalidServiceConfiguration = errors.New(
		"invalid application service configuration",
	)
	ErrApplicationReadForbidden = errors.New(
		"application read forbidden",
	)
	ErrApplicationManagementForbidden = errors.New(
		"application management forbidden",
	)
	ErrInvalidApplication = errors.New(
		"invalid application",
	)
	ErrApplicationNotFound = errors.New(
		"application not found",
	)
	ErrApplicationRoleNotFound = errors.New(
		"application access role not found",
	)
	ErrApplicationClientIDUnavailable = errors.New(
		"application client ID unavailable",
	)
)

type Service struct {
	pool    *pgxpool.Pool
	queries *store.Queries
}

type CreateApplicationInput struct {
	Name           string
	Description    string
	ClientType     ClientType
	RedirectURIs   []string
	AccessMode     AccessMode
	AllowedRoleIDs []pgtype.UUID
}

type ApplicationSummary struct {
	ApplicationID    pgtype.UUID
	Name             string
	Description      string
	ClientID         string
	ClientType       ClientType
	Status           string
	AccessMode       AccessMode
	RedirectURICount int32
	AllowedRoleCount int32
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type RedirectURISummary struct {
	RedirectURIID pgtype.UUID
	URI           string
	CreatedAt     time.Time
}

type ApplicationAccessRole struct {
	RoleID   pgtype.UUID
	RoleKey  string
	Name     string
	IsSystem bool
}

type ApplicationDetail struct {
	ApplicationID pgtype.UUID
	Name          string
	Description   string
	ClientID      string
	ClientType    ClientType
	Status        string
	AccessMode    AccessMode
	CreatedAt     time.Time
	UpdatedAt     time.Time
	RedirectURIs  []RedirectURISummary
	AllowedRoles  []ApplicationAccessRole
}

type CreateApplicationResult struct {
	Application  ApplicationDetail
	ClientSecret string
}

func NewService(
	pool *pgxpool.Pool,
) (*Service, error) {
	if pool == nil {
		return nil, ErrInvalidServiceConfiguration
	}

	return &Service{
		pool:    pool,
		queries: store.New(pool),
	}, nil
}
