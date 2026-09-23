package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/audit"
	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

type ConnectionStatus string

const (
	ConnectionStatusEnabled  ConnectionStatus = "enabled"
	ConnectionStatusDisabled ConnectionStatus = "disabled"
)

var (
	ErrInvalidManagementService = errors.New(
		"invalid federation management service",
	)
	ErrFederationManagementForbidden = errors.New(
		"federation management forbidden",
	)
	ErrInvalidFederationConnection = errors.New(
		"invalid upstream federation connection",
	)
	ErrFederationConnectionNotFound = errors.New(
		"upstream federation connection not found",
	)
)

type ManagementService struct {
	pool         *pgxpool.Pool
	queries      *store.Queries
	discovery    ProviderDiscovery
	secretCipher SecretCipher
	auditWriter  audit.EventWriter
}

type SaveConnectionInput struct {
	DisplayName  string
	Issuer       string
	ClientID     string
	ClientSecret string
}

type ConnectionSummary struct {
	ConnectionID pgtype.UUID
	DisplayName  string
	Issuer       string
	ClientID     string
	Status       ConnectionStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func NewManagementService(
	pool *pgxpool.Pool,
	discovery ProviderDiscovery,
	secretCipher SecretCipher,
	auditWriter audit.EventWriter,
) (*ManagementService, error) {
	if pool == nil ||
		discovery == nil ||
		secretCipher == nil ||
		auditWriter == nil {
		return nil, ErrInvalidManagementService
	}

	return &ManagementService{
		pool:         pool,
		queries:      store.New(pool),
		discovery:    discovery,
		secretCipher: secretCipher,
		auditWriter:  auditWriter,
	}, nil
}

func (service *ManagementService) GetConnection(
	ctx context.Context,
	session auth.SessionContext,
) (ConnectionSummary, error) {
	if !session.HasPermission(
		auth.PermissionFederationManage,
	) {
		return ConnectionSummary{},
			ErrFederationManagementForbidden
	}

	connection, err :=
		service.queries.GetTenantUpstreamOIDCConnection(
			ctx,
			session.TenantID,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionSummary{},
			ErrFederationConnectionNotFound
	}
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"load upstream connection: %w",
			err,
		)
	}

	return summarizeConnection(connection), nil
}

func (service *ManagementService) SaveConnection(
	ctx context.Context,
	session auth.SessionContext,
	input SaveConnectionInput,
) (ConnectionSummary, error) {
	if !session.HasPermission(
		auth.PermissionFederationManage,
	) {
		return ConnectionSummary{},
			ErrFederationManagementForbidden
	}

	displayName := strings.TrimSpace(
		input.DisplayName,
	)
	issuer := strings.TrimSpace(input.Issuer)
	clientID := strings.TrimSpace(
		input.ClientID,
	)

	if displayName != input.DisplayName ||
		!validSensitiveValue(displayName, 100) ||
		issuer != input.Issuer ||
		!validSensitiveValue(issuer, 2048) ||
		clientID != input.ClientID ||
		!validSensitiveValue(
			clientID,
			maxClientIDBytes,
		) ||
		!validSensitiveValue(
			input.ClientSecret,
			maxClientSecretBytes,
		) {
		return ConnectionSummary{},
			ErrInvalidFederationConnection
	}

	document, err := service.discovery.Discover(
		ctx,
		issuer,
	)
	if err != nil ||
		document.Issuer != issuer {
		return ConnectionSummary{},
			ErrInvalidFederationConnection
	}

	clientSecret := []byte(input.ClientSecret)
	defer clear(clientSecret)

	encryptedSecret, err :=
		service.secretCipher.Encrypt(
			session.TenantID,
			SecretPurposeClientSecret,
			clientSecret,
		)
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"encrypt upstream client secret: %w",
			err,
		)
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"begin upstream connection transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(
			context.Background(),
		)
	}()

	queries := service.queries.WithTx(
		transaction,
	)

	connection, err :=
		queries.UpsertUpstreamOIDCConnection(
			ctx,
			store.UpsertUpstreamOIDCConnectionParams{
				TenantID:    session.TenantID,
				DisplayName: displayName,
				Issuer:      issuer,
				ClientID:    clientID,

				ClientSecretCiphertext: encryptedSecret.Ciphertext,
				ClientSecretNonce:      encryptedSecret.Nonce,
				EncryptionKeyID:        encryptedSecret.KeyID,
			},
		)
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"save upstream connection: %w",
			err,
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type: audit.
				EventFederationConnectionSaved,
			Outcome:     audit.OutcomeSuccess,
			SubjectType: "upstream_oidc_connection",
			SubjectID:   connection.ID,
			Metadata: audit.Metadata{
				"connection_status": connection.Status,
			},
		},
	)
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"audit upstream connection save: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"commit upstream connection: %w",
			err,
		)
	}

	return summarizeConnection(connection), nil
}

func (service *ManagementService) SetConnectionStatus(
	ctx context.Context,
	session auth.SessionContext,
	status ConnectionStatus,
) (ConnectionSummary, error) {
	if !session.HasPermission(
		auth.PermissionFederationManage,
	) {
		return ConnectionSummary{},
			ErrFederationManagementForbidden
	}

	if status != ConnectionStatusEnabled &&
		status != ConnectionStatusDisabled {
		return ConnectionSummary{},
			ErrInvalidFederationConnection
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"begin connection status transaction: %w",
			err,
		)
	}

	defer func() {
		_ = transaction.Rollback(
			context.Background(),
		)
	}()

	queries := service.queries.WithTx(
		transaction,
	)

	current, err :=
		queries.GetTenantUpstreamOIDCConnectionForUpdate(
			ctx,
			session.TenantID,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionSummary{},
			ErrFederationConnectionNotFound
	}
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"lock upstream connection: %w",
			err,
		)
	}

	if current.Status == string(status) {
		return summarizeConnection(current), nil
	}

	updated, err :=
		queries.SetUpstreamOIDCConnectionStatus(
			ctx,
			store.SetUpstreamOIDCConnectionStatusParams{
				Status:       string(status),
				TenantID:     session.TenantID,
				ConnectionID: current.ID,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionSummary{},
			ErrFederationConnectionNotFound
	}
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"update upstream connection status: %w",
			err,
		)
	}

	_, err = service.auditWriter.Write(
		ctx,
		queries,
		audit.Event{
			TenantID:          session.TenantID,
			ActorKind:         audit.ActorUser,
			ActorUserID:       session.UserID,
			ActorMembershipID: session.MembershipID,
			SessionID:         session.SessionID,
			Type: audit.
				EventFederationConnectionStatusChanged,
			Outcome:     audit.OutcomeSuccess,
			SubjectType: "upstream_oidc_connection",
			SubjectID:   updated.ID,
			Metadata: audit.Metadata{
				"previous_status": current.Status,
				"new_status":      updated.Status,
			},
		},
	)
	if err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"audit connection status update: %w",
			err,
		)
	}

	if err := transaction.Commit(ctx); err != nil {
		return ConnectionSummary{}, fmt.Errorf(
			"commit connection status update: %w",
			err,
		)
	}

	return summarizeConnection(updated), nil
}

func summarizeConnection(
	connection store.UpstreamOidcConnection,
) ConnectionSummary {
	return ConnectionSummary{
		ConnectionID: connection.ID,
		DisplayName:  connection.DisplayName,
		Issuer:       connection.Issuer,
		ClientID:     connection.ClientID,
		Status: ConnectionStatus(
			connection.Status,
		),
		CreatedAt: connection.CreatedAt.Time,
		UpdatedAt: connection.UpdatedAt.Time,
	}
}
