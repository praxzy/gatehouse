package federation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/praxzy/gatehouse/backend/internal/auth"
	store "github.com/praxzy/gatehouse/backend/internal/store/db"
)

const maxProviderErrorBytes = 256

var (
	ErrInvalidCallbackService = errors.New(
		"invalid federation callback service",
	)
	ErrInvalidAuthorizationCallback = errors.New(
		"invalid upstream authorization callback",
	)
	ErrUpstreamAuthorizationDenied = errors.New(
		"upstream authorization denied",
	)
	ErrUpstreamIdentityNotMapped = errors.New(
		"upstream identity is not mapped",
	)
)

type CallbackStore interface {
	ConsumeUpstreamOIDCTransaction(
		context.Context,
		[]byte,
	) (store.UpstreamOidcTransaction, error)

	GetEnabledUpstreamOIDCConnectionByID(
		context.Context,
		store.GetEnabledUpstreamOIDCConnectionByIDParams,
	) (store.UpstreamOidcConnection, error)
}

type TokenExchanger interface {
	Exchange(
		context.Context,
		TokenExchangeInput,
	) (TokenResponse, error)
}

type UpstreamIdentityVerifier interface {
	Verify(
		context.Context,
		IDTokenVerificationInput,
	) (VerifiedIdentity, error)
}

type UpstreamSessionIssuer interface {
	CreateUpstreamSession(
		context.Context,
		auth.CreateUpstreamSessionInput,
	) (auth.SessionGrant, error)
}

type AuthorizationCallbackService struct {
	store        CallbackStore
	discovery    ProviderDiscovery
	tokenClient  TokenExchanger
	verifier     UpstreamIdentityVerifier
	secretCipher SecretCipher
	sessions     UpstreamSessionIssuer
	redirectURI  string
}

type CompleteAuthorizationInput struct {
	State           string
	Code            string
	ProviderError   string
	PreviousSession string
}

type CompleteAuthorizationResult struct {
	Session    auth.SessionGrant
	ReturnPath string
}

func NewAuthorizationCallbackService(
	callbackStore CallbackStore,
	discovery ProviderDiscovery,
	tokenClient TokenExchanger,
	verifier UpstreamIdentityVerifier,
	secretCipher SecretCipher,
	sessions UpstreamSessionIssuer,
	redirectURI string,
) (*AuthorizationCallbackService, error) {
	if callbackStore == nil ||
		discovery == nil ||
		tokenClient == nil ||
		verifier == nil ||
		secretCipher == nil ||
		sessions == nil ||
		!validFederationRedirectURI(redirectURI) {
		return nil, ErrInvalidCallbackService
	}

	return &AuthorizationCallbackService{
		store:        callbackStore,
		discovery:    discovery,
		tokenClient:  tokenClient,
		verifier:     verifier,
		secretCipher: secretCipher,
		sessions:     sessions,
		redirectURI:  redirectURI,
	}, nil
}

func (service *AuthorizationCallbackService) Complete(
	ctx context.Context,
	input CompleteAuthorizationInput,
) (CompleteAuthorizationResult, error) {
	if service == nil ||
		service.store == nil ||
		service.discovery == nil ||
		service.tokenClient == nil ||
		service.verifier == nil ||
		service.secretCipher == nil ||
		service.sessions == nil {
		return CompleteAuthorizationResult{},
			ErrInvalidCallbackService
	}

	stateHash, err := HashAuthorizationState(
		input.State,
	)
	if err != nil {
		return CompleteAuthorizationResult{},
			ErrInvalidAuthorizationCallback
	}

	transaction, err :=
		service.store.ConsumeUpstreamOIDCTransaction(
			ctx,
			stateHash,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return CompleteAuthorizationResult{},
			ErrInvalidAuthorizationCallback
	}
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"consume upstream transaction: %w",
				err,
			)
	}

	if err := validateConsumedTransaction(
		transaction,
		stateHash,
	); err != nil {
		return CompleteAuthorizationResult{}, err
	}

	if input.ProviderError != "" {
		if input.Code != "" ||
			!validSensitiveValue(
				input.ProviderError,
				maxProviderErrorBytes,
			) {
			return CompleteAuthorizationResult{},
				ErrInvalidAuthorizationCallback
		}

		return CompleteAuthorizationResult{},
			ErrUpstreamAuthorizationDenied
	}

	if !validSensitiveValue(
		input.Code,
		maxAuthorizationCode,
	) {
		return CompleteAuthorizationResult{},
			ErrInvalidAuthorizationCallback
	}

	connection, err :=
		service.store.GetEnabledUpstreamOIDCConnectionByID(
			ctx,
			store.GetEnabledUpstreamOIDCConnectionByIDParams{
				TenantID: transaction.TenantID,

				ConnectionID: transaction.ConnectionID,
			},
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return CompleteAuthorizationResult{},
			ErrFederationUnavailable
	}
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"load upstream connection: %w",
				err,
			)
	}

	if err := validateCallbackConnection(
		connection,
		transaction,
	); err != nil {
		return CompleteAuthorizationResult{}, err
	}

	document, err := service.discovery.Discover(
		ctx,
		connection.Issuer,
	)
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"%w: discovery failed",
				ErrFederationUnavailable,
			)
	}

	pkceVerifier, err :=
		service.secretCipher.Decrypt(
			transaction.TenantID,
			SecretPurposePKCEVerifier,
			EncryptedSecret{
				Ciphertext: transaction.PkceVerifierCiphertext,
				Nonce:      transaction.PkceVerifierNonce,
				KeyID:      transaction.EncryptionKeyID,
			},
		)
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"%w: decrypt transaction",
				ErrFederationUnavailable,
			)
	}
	defer clear(pkceVerifier)

	clientSecret, err :=
		service.secretCipher.Decrypt(
			connection.TenantID,
			SecretPurposeClientSecret,
			EncryptedSecret{
				Ciphertext: connection.ClientSecretCiphertext,
				Nonce:      connection.ClientSecretNonce,
				KeyID:      connection.EncryptionKeyID,
			},
		)
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"%w: decrypt client credentials",
				ErrFederationUnavailable,
			)
	}
	defer clear(clientSecret)

	tokenResponse, err := service.tokenClient.Exchange(
		ctx,
		TokenExchangeInput{
			TokenEndpoint: document.TokenEndpoint,
			ClientID:      connection.ClientID,
			ClientSecret:  clientSecret,
			Code:          input.Code,
			RedirectURI:   service.redirectURI,
			PKCEVerifier:  string(pkceVerifier),
		},
	)
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"%w: token exchange failed",
				ErrFederationUnavailable,
			)
	}

	identity, err := service.verifier.Verify(
		ctx,
		IDTokenVerificationInput{
			IDToken:        tokenResponse.IDToken,
			ExpectedIssuer: document.Issuer,
			ClientID:       connection.ClientID,
			JWKSURI:        document.JWKSURI,
			NonceHash:      transaction.NonceHash,
		},
	)
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"%w: ID token verification failed",
				ErrFederationUnavailable,
			)
	}

	session, err := service.sessions.CreateUpstreamSession(
		ctx,
		auth.CreateUpstreamSessionInput{
			TenantID:        transaction.TenantID,
			ConnectionID:    transaction.ConnectionID,
			Subject:         identity.Subject,
			PreviousSession: input.PreviousSession,
		},
	)
	if errors.Is(err, auth.ErrInactiveMembership) {
		return CompleteAuthorizationResult{},
			ErrUpstreamIdentityNotMapped
	}
	if err != nil {
		return CompleteAuthorizationResult{},
			fmt.Errorf(
				"create upstream session: %w",
				err,
			)
	}

	return CompleteAuthorizationResult{
		Session:    session,
		ReturnPath: transaction.ReturnPath,
	}, nil
}

func validateConsumedTransaction(
	transaction store.UpstreamOidcTransaction,
	expectedStateHash []byte,
) error {
	if !transaction.TenantID.Valid ||
		!transaction.ConnectionID.Valid ||
		!transaction.ConsumedAt.Valid ||
		len(transaction.StateHash) != sha256.Size ||
		len(transaction.NonceHash) != sha256.Size ||
		subtle.ConstantTimeCompare(
			transaction.StateHash,
			expectedStateHash,
		) != 1 ||
		!validFederationReturnPath(
			transaction.ReturnPath,
		) {
		return ErrInvalidAuthorizationCallback
	}

	return nil
}

func validateCallbackConnection(
	connection store.UpstreamOidcConnection,
	transaction store.UpstreamOidcTransaction,
) error {
	if !connection.ID.Valid ||
		!connection.TenantID.Valid ||
		connection.ID != transaction.ConnectionID ||
		connection.TenantID != transaction.TenantID ||
		connection.Status != "enabled" ||
		!validSensitiveValue(
			connection.Issuer,
			2048,
		) ||
		!validSensitiveValue(
			connection.ClientID,
			maxClientIDBytes,
		) {
		return ErrFederationUnavailable
	}

	return nil
}
