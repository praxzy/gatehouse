package oidcclient

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrTokenExchange = errors.New(
		"OIDC token exchange failed",
	)
	ErrInvalidIDToken = errors.New(
		"invalid OIDC ID token",
	)
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

type Identity struct {
	Subject            string
	Name               string
	Email              string
	Roles              []string
	AuthenticationTime time.Time
	ExpiresAt          time.Time
}

type idTokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type idTokenClaims struct {
	Issuer             string   `json:"iss"`
	Subject            string   `json:"sub"`
	Audience           audience `json:"aud"`
	ExpiresAt          int64    `json:"exp"`
	IssuedAt           int64    `json:"iat"`
	AuthenticationTime int64    `json:"auth_time"`
	Nonce              string   `json:"nonce"`
	Name               string   `json:"name"`
	Email              string   `json:"email"`
	EmailVerified      bool     `json:"email_verified"`
	Roles              []string `json:"roles"`
}

type audience []string

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func (client *Client) ExchangeAndVerify(
	ctx context.Context,
	provider Provider,
	code string,
	codeVerifier string,
	expectedNonce string,
) (Identity, TokenResponse, error) {
	tokens, err := client.ExchangeAuthorizationCode(
		ctx,
		provider,
		code,
		codeVerifier,
	)
	if err != nil {
		return Identity{}, TokenResponse{}, err
	}

	identity, err := client.VerifyIDToken(
		ctx,
		provider,
		tokens.IDToken,
		expectedNonce,
	)
	if err != nil {
		return Identity{}, TokenResponse{}, err
	}

	return identity, tokens, nil
}

func (client *Client) ExchangeAuthorizationCode(
	ctx context.Context,
	provider Provider,
	code string,
	codeVerifier string,
) (TokenResponse, error) {
	if code == "" || codeVerifier == "" {
		return TokenResponse{}, ErrTokenExchange
	}

	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {client.redirect},
		"code_verifier": {codeVerifier},
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		provider.TokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return TokenResponse{}, fmt.Errorf(
			"create token request: %w",
			err,
		)
	}

	request.Header.Set(
		"Content-Type",
		"application/x-www-form-urlencoded",
	)
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(client.clientID, client.secret)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return TokenResponse{}, fmt.Errorf(
			"request token exchange: %w",
			err,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return TokenResponse{}, ErrTokenExchange
	}

	var tokens TokenResponse
	if err := decodeLimitedJSON(response.Body, &tokens); err != nil ||
		tokens.AccessToken == "" ||
		tokens.TokenType != "Bearer" ||
		tokens.ExpiresIn <= 0 ||
		tokens.IDToken == "" {
		return TokenResponse{}, ErrTokenExchange
	}

	return tokens, nil
}

func (client *Client) VerifyIDToken(
	ctx context.Context,
	provider Provider,
	rawToken string,
	expectedNonce string,
) (Identity, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 || expectedNonce == "" {
		return Identity{}, ErrInvalidIDToken
	}

	headerBytes, err := decodeJWTPart(parts[0])
	if err != nil {
		return Identity{}, err
	}

	var header idTokenHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil ||
		header.Algorithm != "RS256" ||
		header.Type != "JWT" ||
		header.KeyID == "" {
		return Identity{}, ErrInvalidIDToken
	}

	claimsBytes, err := decodeJWTPart(parts[1])
	if err != nil {
		return Identity{}, err
	}

	var claims idTokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return Identity{}, ErrInvalidIDToken
	}

	key, err := client.fetchSigningKey(
		ctx,
		provider.JWKSURI,
		header.KeyID,
	)
	if err != nil {
		return Identity{}, err
	}

	signature, err := decodeJWTPart(parts[2])
	if err != nil {
		return Identity{}, err
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(
		key,
		crypto.SHA256,
		digest[:],
		signature,
	); err != nil {
		return Identity{}, ErrInvalidIDToken
	}

	now := client.now().UTC()
	if claims.Issuer != provider.Issuer ||
		claims.Subject == "" ||
		!claims.Audience.contains(client.clientID) ||
		claims.ExpiresAt <= now.Unix() ||
		claims.IssuedAt <= 0 ||
		claims.IssuedAt > now.Add(time.Minute).Unix() ||
		claims.AuthenticationTime <= 0 ||
		claims.AuthenticationTime > claims.IssuedAt ||
		subtle.ConstantTimeCompare(
			[]byte(claims.Nonce),
			[]byte(expectedNonce),
		) != 1 ||
		claims.Name == "" ||
		claims.Email == "" ||
		!claims.EmailVerified ||
		!validRoles(claims.Roles) {
		return Identity{}, ErrInvalidIDToken
	}

	return Identity{
		Subject: claims.Subject,
		Name:    claims.Name,
		Email:   claims.Email,
		Roles: append(
			[]string(nil),
			claims.Roles...,
		),
		AuthenticationTime: time.Unix(
			claims.AuthenticationTime,
			0,
		).UTC(),
		ExpiresAt: time.Unix(
			claims.ExpiresAt,
			0,
		).UTC(),
	}, nil
}

func (client *Client) fetchSigningKey(
	ctx context.Context,
	jwksURI string,
	keyID string,
) (*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		jwksURI,
		nil,
	)
	if err != nil {
		return nil, ErrInvalidIDToken
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"request provider JWKS: %w",
			err,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, ErrInvalidIDToken
	}

	var keySet jsonWebKeySet
	if err := decodeLimitedJSON(response.Body, &keySet); err != nil {
		return nil, ErrInvalidIDToken
	}

	var matchingKeys []jsonWebKey
	for _, key := range keySet.Keys {
		if key.KeyID == keyID {
			matchingKeys = append(matchingKeys, key)
		}
	}

	if len(matchingKeys) != 1 {
		return nil, ErrInvalidIDToken
	}

	return rsaPublicKey(matchingKeys[0])
}

func rsaPublicKey(key jsonWebKey) (*rsa.PublicKey, error) {
	if key.KeyType != "RSA" ||
		key.Use != "sig" ||
		key.Algorithm != "RS256" ||
		key.Modulus == "" ||
		key.Exponent == "" {
		return nil, ErrInvalidIDToken
	}

	modulus, err := base64.RawURLEncoding.DecodeString(
		key.Modulus,
	)
	if err != nil {
		return nil, ErrInvalidIDToken
	}

	exponentBytes, err := base64.RawURLEncoding.DecodeString(
		key.Exponent,
	)
	if err != nil {
		return nil, ErrInvalidIDToken
	}

	exponent := new(big.Int).SetBytes(exponentBytes)
	if !exponent.IsInt64() ||
		exponent.Int64() < 3 ||
		exponent.Int64()%2 == 0 ||
		strconv.IntSize == 32 &&
			exponent.Int64() > int64(^uint(0)>>1) {
		return nil, ErrInvalidIDToken
	}

	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(exponent.Int64()),
	}
	if publicKey.N.BitLen() < 2048 {
		return nil, ErrInvalidIDToken
	}

	return publicKey, nil
}

func decodeJWTPart(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrInvalidIDToken
	}

	return decoded, nil
}

func decodeLimitedJSON(reader io.Reader, target any) error {
	limited := io.LimitReader(
		reader,
		maximumProviderResponseBytes+1,
	)
	body, err := io.ReadAll(limited)
	if err != nil ||
		len(body) > maximumProviderResponseBytes {
		return errors.New("invalid JSON response")
	}

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	if err := decoder.Decode(target); err != nil {
		return err
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("multiple JSON values")
	}

	return nil
}

func (value *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			return ErrInvalidIDToken
		}
		*value = audience{single}
		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil ||
		len(multiple) == 0 {
		return ErrInvalidIDToken
	}
	for _, item := range multiple {
		if item == "" {
			return ErrInvalidIDToken
		}
	}

	*value = append((*value)[:0], multiple...)
	return nil
}

func (value audience) contains(expected string) bool {
	for _, item := range value {
		if item == expected {
			return true
		}
	}

	return false
}

func validRoles(roles []string) bool {
	for _, role := range roles {
		if role == "" || role != strings.TrimSpace(role) {
			return false
		}
	}

	return true
}
