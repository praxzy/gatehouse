package federation

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

const (
	maxJWKSBytes      int64 = 1 << 20
	maxJWKSKeys             = 100
	maxJWKKeyIDBytes        = 256
	minRSAModulusBits       = 2048
	maxRSAModulusBits       = 8192
	maxRSAExponent          = 1<<31 - 1
)

var (
	ErrInvalidJWKSClient = errors.New(
		"invalid upstream JWKS client",
	)
	ErrInvalidJWKSURI = errors.New(
		"invalid upstream JWKS URI",
	)
	ErrJWKSUnavailable = errors.New(
		"upstream JWKS unavailable",
	)
	ErrInvalidJWKS = errors.New(
		"invalid upstream JWKS",
	)
	ErrSigningKeyUnavailable = errors.New(
		"upstream signing key unavailable",
	)
)

type SigningKeySource interface {
	GetRSASigningKey(
		context.Context,
		string,
		string,
	) (*rsa.PublicKey, error)
}

type JWKSClient struct {
	provider *ProviderHTTPClient
}

type jwksDocument struct {
	Keys []json.RawMessage `json:"keys"`
}

type rsaJWK struct {
	KeyType  string `json:"kty"`
	Use      string `json:"use"`
	KeyID    string `json:"kid"`
	Alg      string `json:"alg"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

func NewJWKSClient(
	provider *ProviderHTTPClient,
) (*JWKSClient, error) {
	if provider == nil ||
		provider.httpClient == nil {
		return nil, ErrInvalidJWKSClient
	}

	return &JWKSClient{
		provider: provider,
	}, nil
}

func (client *JWKSClient) GetRSASigningKey(
	ctx context.Context,
	jwksURI string,
	keyID string,
) (*rsa.PublicKey, error) {
	if client == nil ||
		client.provider == nil {
		return nil, ErrInvalidJWKSClient
	}

	if !validSensitiveValue(
		keyID,
		maxJWKKeyIDBytes,
	) {
		return nil, ErrSigningKeyUnavailable
	}

	if _, err := parseProviderURL(
		jwksURI,
		client.provider.policy,
	); err != nil {
		return nil, ErrInvalidJWKSURI
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		jwksURI,
		nil,
	)
	if err != nil {
		return nil, ErrInvalidJWKSURI
	}

	request.Header.Set(
		"Accept",
		"application/json",
	)

	response, err := client.provider.Do(request)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: request failed",
			ErrJWKSUnavailable,
		)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"%w: status %d",
			ErrJWKSUnavailable,
			response.StatusCode,
		)
	}

	payload, err := io.ReadAll(
		io.LimitReader(
			response.Body,
			maxJWKSBytes+1,
		),
	)
	if err != nil {
		return nil, ErrJWKSUnavailable
	}

	if int64(len(payload)) > maxJWKSBytes {
		return nil, ErrInvalidJWKS
	}

	if err := rejectDuplicateJSONObjectMembers(
		payload,
	); err != nil {
		return nil, ErrInvalidJWKS
	}

	decoder := json.NewDecoder(
		bytes.NewReader(payload),
	)

	var document jwksDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalidJWKS
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrInvalidJWKS
	}

	if len(document.Keys) == 0 ||
		len(document.Keys) > maxJWKSKeys {
		return nil, ErrInvalidJWKS
	}

	var selected *rsa.PublicKey
	matches := 0

	for _, rawKey := range document.Keys {
		if err := rejectDuplicateJSONObjectMembers(
			rawKey,
		); err != nil {
			return nil, ErrInvalidJWKS
		}

		var candidate rsaJWK
		if err := json.Unmarshal(
			rawKey,
			&candidate,
		); err != nil {
			return nil, ErrInvalidJWKS
		}

		if candidate.KeyID != keyID {
			continue
		}

		matches++
		if matches > 1 {
			return nil, ErrInvalidJWKS
		}

		publicKey, err := parseRSAJWK(candidate)
		if err != nil {
			return nil, err
		}

		selected = publicKey
	}

	if matches != 1 || selected == nil {
		return nil, ErrSigningKeyUnavailable
	}

	return selected, nil
}

func parseRSAJWK(
	key rsaJWK,
) (*rsa.PublicKey, error) {
	if key.KeyType != "RSA" ||
		(key.Use != "" && key.Use != "sig") ||
		(key.Alg != "" && key.Alg != "RS256") ||
		!validSensitiveValue(
			key.KeyID,
			maxJWKKeyIDBytes,
		) {
		return nil, ErrInvalidJWKS
	}

	modulusBytes, err :=
		decodeCanonicalBase64URL(key.Modulus)
	if err != nil ||
		len(modulusBytes) == 0 ||
		modulusBytes[0] == 0 {
		return nil, ErrInvalidJWKS
	}

	modulus := new(big.Int).SetBytes(
		modulusBytes,
	)
	if modulus.BitLen() < minRSAModulusBits ||
		modulus.BitLen() > maxRSAModulusBits ||
		modulus.Bit(0) != 1 {
		return nil, ErrInvalidJWKS
	}

	exponentBytes, err :=
		decodeCanonicalBase64URL(key.Exponent)
	if err != nil ||
		len(exponentBytes) == 0 ||
		len(exponentBytes) > 4 ||
		exponentBytes[0] == 0 {
		return nil, ErrInvalidJWKS
	}

	var exponent uint64
	for _, value := range exponentBytes {
		exponent = exponent<<8 |
			uint64(value)
	}

	if exponent < 3 ||
		exponent > maxRSAExponent ||
		exponent%2 == 0 {
		return nil, ErrInvalidJWKS
	}

	return &rsa.PublicKey{
		N: modulus,
		E: int(exponent),
	}, nil
}

func decodeCanonicalBase64URL(
	value string,
) ([]byte, error) {
	if value == "" {
		return nil, ErrInvalidJWKS
	}

	decoded, err :=
		base64.RawURLEncoding.DecodeString(
			value,
		)
	if err != nil ||
		base64.RawURLEncoding.EncodeToString(
			decoded,
		) != value {
		return nil, ErrInvalidJWKS
	}

	return decoded, nil
}

func rejectDuplicateJSONObjectMembers(
	payload []byte,
) error {
	decoder := json.NewDecoder(
		bytes.NewReader(payload),
	)

	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return ErrInvalidJWKS
	}

	seen := make(map[string]struct{})

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		name, ok := token.(string)
		if !ok {
			return ErrInvalidJWKS
		}

		if _, exists := seen[name]; exists {
			return ErrInvalidJWKS
		}
		seen[name] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}

	token, err = decoder.Token()
	if err != nil {
		return err
	}

	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != '}' {
		return ErrInvalidJWKS
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidJWKS
	}

	return nil
}

var _ SigningKeySource = (*JWKSClient)(nil)
