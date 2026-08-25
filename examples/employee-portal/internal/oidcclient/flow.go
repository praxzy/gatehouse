package oidcclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
)

var ErrFlowGeneration = errors.New(
	"generate OIDC authorization flow",
)

type AuthorizationFlow struct {
	State        string
	Nonce        string
	CodeVerifier string
}

func NewAuthorizationFlow() (AuthorizationFlow, error) {
	return newAuthorizationFlow(rand.Reader)
}

func newAuthorizationFlow(
	random io.Reader,
) (AuthorizationFlow, error) {
	state, err := randomValue(random)
	if err != nil {
		return AuthorizationFlow{}, err
	}

	nonce, err := randomValue(random)
	if err != nil {
		return AuthorizationFlow{}, err
	}

	verifier, err := randomValue(random)
	if err != nil {
		return AuthorizationFlow{}, err
	}

	return AuthorizationFlow{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
	}, nil
}

func (client *Client) AuthorizationURL(
	provider Provider,
	flow AuthorizationFlow,
) (string, error) {
	endpoint, err := url.Parse(provider.AuthorizationEndpoint)
	if err != nil ||
		flow.State == "" ||
		flow.Nonce == "" ||
		flow.CodeVerifier == "" {
		return "", ErrInvalidProvider
	}

	challenge := sha256.Sum256(
		[]byte(flow.CodeVerifier),
	)

	query := endpoint.Query()
	query.Set("response_type", "code")
	query.Set("client_id", client.clientID)
	query.Set("redirect_uri", client.redirect)
	query.Set("scope", "openid profile email")
	query.Set("state", flow.State)
	query.Set("nonce", flow.Nonce)
	query.Set(
		"code_challenge",
		base64.RawURLEncoding.EncodeToString(
			challenge[:],
		),
	)
	query.Set("code_challenge_method", "S256")
	endpoint.RawQuery = query.Encode()

	return endpoint.String(), nil
}

func randomValue(random io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", ErrFlowGeneration
	}

	return base64.RawURLEncoding.EncodeToString(value), nil
}
