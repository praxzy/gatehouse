package federation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const authorizationTransactionTTL = 5 * time.Minute

var (
	ErrInvalidAuthorizationService = errors.New(
		"invalid federation authorization service",
	)
	ErrInvalidBeginRequest = errors.New(
		"invalid federation begin request",
	)
	ErrFederationUnavailable = errors.New(
		"upstream federation unavailable",
	)
)

var tenantSlugPattern = regexp.MustCompile(
	`^[a-z0-9]+(?:-[a-z0-9]+)*$`,
)

type AuthorizationStore interface {
	GetEnabledUpstreamOIDCConnectionByTenantSlug(
		context.Context,
		string,
	) (store.UpstreamOidcConnection, error)

	CreateUpstreamOIDCTransaction(
		context.Context,
		store.CreateUpstreamOIDCTransactionParams,
	) (store.UpstreamOidcTransaction, error)
}

type ProviderDiscovery interface {
	Discover(
		context.Context,
		string,
	) (DiscoveryDocument, error)
}

type AuthorizationService struct {
	store        AuthorizationStore
	discovery    ProviderDiscovery
	secretCipher SecretCipher
	redirectURI  string
	now          func() time.Time
}

type BeginAuthorizationInput struct {
	TenantSlug string
	ReturnPath string
}

type BeginAuthorizationResult struct {
	AuthorizationURL string
	ConnectionName   string
	ExpiresAt        time.Time
}

func NewAuthorizationService(
	authorizationStore AuthorizationStore,
	discovery ProviderDiscovery,
	secretCipher SecretCipher,
	redirectURI string,
) (*AuthorizationService, error) {
	if authorizationStore == nil ||
		discovery == nil ||
		secretCipher == nil ||
		!validFederationRedirectURI(redirectURI) {
		return nil, ErrInvalidAuthorizationService
	}

	return &AuthorizationService{
		store:        authorizationStore,
		discovery:    discovery,
		secretCipher: secretCipher,
		redirectURI:  redirectURI,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}, nil
}

func (service *AuthorizationService) Begin(
	ctx context.Context,
	input BeginAuthorizationInput,
) (BeginAuthorizationResult, error) {
	if service == nil ||
		service.store == nil ||
		service.discovery == nil ||
		service.secretCipher == nil ||
		service.now == nil {
		return BeginAuthorizationResult{},
			ErrInvalidAuthorizationService
	}

	returnPath := input.ReturnPath
	if returnPath == "" {
		returnPath = "/"
	}

	if !validTenantSlug(input.TenantSlug) ||
		!validFederationReturnPath(returnPath) {
		return BeginAuthorizationResult{},
			ErrInvalidBeginRequest
	}

	connection, err :=
		service.store.
			GetEnabledUpstreamOIDCConnectionByTenantSlug(
				ctx,
				input.TenantSlug,
			)
	if errors.Is(err, pgx.ErrNoRows) {
		return BeginAuthorizationResult{},
			ErrFederationUnavailable
	}
	if err != nil {
		return BeginAuthorizationResult{},
			fmt.Errorf(
				"load upstream connection: %w",
				err,
			)
	}

	if !connection.ID.Valid ||
		!connection.TenantID.Valid ||
		connection.Status != "enabled" ||
		strings.TrimSpace(connection.Issuer) == "" ||
		strings.TrimSpace(connection.ClientID) == "" ||
		strings.TrimSpace(connection.DisplayName) == "" {
		return BeginAuthorizationResult{},
			ErrFederationUnavailable
	}

	document, err := service.discovery.Discover(
		ctx,
		connection.Issuer,
	)
	if err != nil {
		return BeginAuthorizationResult{},
			fmt.Errorf(
				"%w: discovery failed",
				ErrFederationUnavailable,
			)
	}

	artifacts, err :=
		GenerateAuthorizationArtifacts()
	if err != nil {
		return BeginAuthorizationResult{}, err
	}

	encryptedVerifier, err :=
		service.secretCipher.Encrypt(
			connection.TenantID,
			SecretPurposePKCEVerifier,
			[]byte(artifacts.PKCEVerifier),
		)
	if err != nil {
		return BeginAuthorizationResult{},
			fmt.Errorf(
				"encrypt PKCE verifier: %w",
				err,
			)
	}

	expiresAt := service.now().
		Add(authorizationTransactionTTL)

	_, err = service.store.
		CreateUpstreamOIDCTransaction(
			ctx,
			store.CreateUpstreamOIDCTransactionParams{
				StateHash: artifacts.StateHash,

				TenantID:     connection.TenantID,
				ConnectionID: connection.ID,

				NonceHash: artifacts.NonceHash,

				PkceVerifierCiphertext: encryptedVerifier.Ciphertext,
				PkceVerifierNonce:      encryptedVerifier.Nonce,
				EncryptionKeyID:        encryptedVerifier.KeyID,

				ReturnPath: returnPath,
				ExpiresAt: pgtype.Timestamptz{
					Time:  expiresAt,
					Valid: true,
				},
			},
		)
	if err != nil {
		return BeginAuthorizationResult{},
			fmt.Errorf(
				"create upstream authorization transaction: %w",
				err,
			)
	}

	authorizationURL, err := url.Parse(
		document.AuthorizationEndpoint,
	)
	if err != nil {
		return BeginAuthorizationResult{},
			ErrFederationUnavailable
	}

	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", connection.ClientID)
	query.Set("redirect_uri", service.redirectURI)
	query.Set("scope", "openid")
	query.Set("state", artifacts.State)
	query.Set("nonce", artifacts.Nonce)
	query.Set(
		"code_challenge",
		artifacts.PKCEChallenge,
	)
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()

	return BeginAuthorizationResult{
		AuthorizationURL: authorizationURL.String(),
		ConnectionName:   connection.DisplayName,
		ExpiresAt:        expiresAt,
	}, nil
}

func validTenantSlug(value string) bool {
	return len(value) >= 1 &&
		len(value) <= 63 &&
		value == strings.ToLower(value) &&
		tenantSlugPattern.MatchString(value)
}

func validFederationReturnPath(
	value string,
) bool {
	if len(value) < 1 ||
		len(value) > 2048 ||
		!strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "//") ||
		strings.Contains(value, `\`) {
		return false
	}

	parsed, err := url.ParseRequestURI(value)
	if err != nil ||
		parsed.IsAbs() ||
		parsed.Host != "" ||
		parsed.Fragment != "" {
		return false
	}

	decodedPath, err := url.PathUnescape(
		parsed.EscapedPath(),
	)
	if err != nil ||
		!strings.HasPrefix(decodedPath, "/") ||
		strings.HasPrefix(decodedPath, "//") ||
		strings.Contains(decodedPath, `\`) {
		return false
	}

	for _, character := range decodedPath {
		if character < 0x20 ||
			character == 0x7f {
			return false
		}
	}

	return true
}

func validFederationRedirectURI(
	rawURI string,
) bool {
	parsed, err := url.Parse(rawURI)
	if err != nil ||
		!parsed.IsAbs() ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return false
	}

	if parsed.Scheme == "https" {
		return true
	}

	if parsed.Scheme != "http" {
		return false
	}

	hostname := strings.ToLower(
		parsed.Hostname(),
	)

	if hostname == "localhost" {
		return true
	}

	address := net.ParseIP(hostname)

	return address != nil &&
		address.IsLoopback()
}

var _ AuthorizationStore = (*store.Queries)(nil)
var _ ProviderDiscovery = (*DiscoveryClient)(nil)
