package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/praxzy/gatehouse/backend/internal/application"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

var (
	ErrInvalidTokenServiceConfiguration = errors.New(
		"invalid token service configuration",
	)
	ErrInvalidTokenClient = errors.New(
		"invalid token client",
	)
	ErrInvalidAuthorizationGrant = errors.New(
		"invalid authorization grant",
	)
)

type TokenClientAuthenticationMethod string

const (
	TokenClientAuthenticationNone TokenClientAuthenticationMethod = "none"

	TokenClientAuthenticationBasic TokenClientAuthenticationMethod = "client_secret_basic"
)

type TokenClientAuthentication struct {
	Method       TokenClientAuthenticationMethod
	ClientID     string
	ClientSecret string
}

type TokenResult struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	IDToken     string
	Scope       string
}

type TokenService struct {
	pool     *pgxpool.Pool
	queries  *store.Queries
	provider *Provider
	now      func() time.Time
}

func NewTokenService(
	pool *pgxpool.Pool,
	provider *Provider,
) (*TokenService, error) {
	if pool == nil ||
		provider == nil ||
		provider.signingKey == nil ||
		provider.signingKey.privateKey == nil ||
		provider.config.Issuer == "" {
		return nil, ErrInvalidTokenServiceConfiguration
	}

	return &TokenService{
		pool:     pool,
		queries:  store.New(pool),
		provider: provider,
		now:      time.Now,
	}, nil
}

func (service *TokenService) ExchangeAuthorizationCode(
	ctx context.Context,
	values url.Values,
	authentication TokenClientAuthentication,
) (TokenResult, error) {
	if service == nil ||
		service.pool == nil ||
		service.queries == nil ||
		service.provider == nil ||
		service.provider.signingKey == nil ||
		service.now == nil {
		return TokenResult{},
			ErrInvalidTokenServiceConfiguration
	}

	request, err := ParseTokenRequest(values)
	if err != nil {
		return TokenResult{}, err
	}

	client, err := service.authenticateTokenClient(
		ctx,
		request,
		authentication,
	)
	if err != nil {
		return TokenResult{}, err
	}

	codeChallenge, err :=
		deriveS256CodeChallenge(request.CodeVerifier)
	if err != nil {
		return TokenResult{}, ErrInvalidAuthorizationGrant
	}

	rawAccessToken, accessTokenHash, err :=
		generateAccessToken()
	if err != nil {
		return TokenResult{}, err
	}

	transaction, err := service.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return TokenResult{},
			fmt.Errorf(
				"begin token exchange transaction: %w",
				err,
			)
	}

	defer func() {
		_ = transaction.Rollback(context.Background())
	}()

	queries := service.queries.WithTx(transaction)
	now := service.now().UTC()

	redeemed, err := queries.RedeemAuthorizationCode(
		ctx,
		store.RedeemAuthorizationCodeParams{
			CodeHash:      hashAuthorizationCode(request.Code),
			ClientID:      client.ClientID,
			RedirectUri:   request.RedirectURI,
			CodeChallenge: codeChallenge,
			TokenHash:     accessTokenHash,
			AccessTokenExpiresAt: pgtype.Timestamptz{
				Time:  now.Add(accessTokenLifetime),
				Valid: true,
			},
		},
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenResult{}, ErrInvalidAuthorizationGrant
	}
	if err != nil {
		return TokenResult{},
			fmt.Errorf(
				"redeem authorization code: %w",
				err,
			)
	}

	if !redeemed.UserID.Valid ||
		!redeemed.AuthenticationTime.Valid ||
		!redeemed.AccessTokenCreatedAt.Valid ||
		!redeemed.AccessTokenExpiresAt.Valid {
		return TokenResult{},
			errors.New(
				"redeemed authorization code has invalid bindings",
			)
	}

	issuedAt := redeemed.AccessTokenCreatedAt.Time.UTC()
	authenticationTime :=
		redeemed.AuthenticationTime.Time.UTC()

	idToken, err := service.provider.signingKey.SignIDToken(
		IDTokenClaims{
			Issuer: service.provider.config.Issuer,
			Subject: uuid.UUID(
				redeemed.UserID.Bytes,
			).String(),
			Audience:           redeemed.ClientID,
			IssuedAt:           issuedAt.Unix(),
			ExpiresAt:          issuedAt.Add(idTokenLifetime).Unix(),
			AuthenticationTime: authenticationTime.Unix(),
			Nonce:              redeemed.Nonce,
			Name:               redeemed.DisplayName,
			Email:              redeemed.Email,
			EmailVerified:      true,
			Roles: append(
				[]string(nil),
				redeemed.Roles...,
			),
		},
	)
	if err != nil {
		return TokenResult{},
			fmt.Errorf("sign ID token: %w", err)
	}

	expiresIn := int64(
		redeemed.AccessTokenExpiresAt.Time.
			Sub(issuedAt).
			Seconds(),
	)
	if expiresIn <= 0 {
		return TokenResult{},
			errors.New(
				"issued access token has invalid expiration",
			)
	}

	if err := transaction.Commit(ctx); err != nil {
		return TokenResult{},
			fmt.Errorf(
				"commit token exchange: %w",
				err,
			)
	}

	return TokenResult{
		AccessToken: rawAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		IDToken:     idToken,
		Scope: strings.Join(
			redeemed.GrantedScope,
			" ",
		),
	}, nil
}

func (service *TokenService) authenticateTokenClient(
	ctx context.Context,
	request TokenRequest,
	authentication TokenClientAuthentication,
) (store.GetActiveTokenClientRow, error) {
	clientID := ""

	switch authentication.Method {
	case TokenClientAuthenticationNone:
		if authentication.ClientID != "" ||
			authentication.ClientSecret != "" ||
			request.ClientID == "" {
			return store.GetActiveTokenClientRow{},
				ErrInvalidTokenClient
		}

		clientID = request.ClientID

	case TokenClientAuthenticationBasic:
		if authentication.ClientID == "" ||
			authentication.ClientSecret == "" ||
			(request.ClientID != "" &&
				request.ClientID != authentication.ClientID) {
			return store.GetActiveTokenClientRow{},
				ErrInvalidTokenClient
		}

		clientID = authentication.ClientID

	default:
		return store.GetActiveTokenClientRow{},
			ErrInvalidTokenClient
	}

	client, err := service.queries.GetActiveTokenClient(
		ctx,
		clientID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.GetActiveTokenClientRow{},
			ErrInvalidTokenClient
	}
	if err != nil {
		return store.GetActiveTokenClientRow{},
			fmt.Errorf("load token client: %w", err)
	}

	switch client.ClientType {
	case "public":
		if authentication.Method !=
			TokenClientAuthenticationNone ||
			len(client.ClientSecretHash) != 0 {
			return store.GetActiveTokenClientRow{},
				ErrInvalidTokenClient
		}

	case "confidential":
		if authentication.Method !=
			TokenClientAuthenticationBasic ||
			!application.VerifyClientSecret(
				authentication.ClientSecret,
				client.ClientSecretHash,
			) {
			return store.GetActiveTokenClientRow{},
				ErrInvalidTokenClient
		}

	default:
		return store.GetActiveTokenClientRow{},
			ErrInvalidTokenClient
	}

	return client, nil
}
