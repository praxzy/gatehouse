package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
)

const (
	minimumRSABits     = 2048
	requiredRSAE       = 65537
	maximumKeyIDLength = 128
)

var (
	ErrInvalidSigningKey = errors.New(
		"invalid OIDC signing key",
	)
	ErrInvalidKeyID = errors.New(
		"invalid OIDC signing key ID",
	)
)

type SigningKey struct {
	keyID      string
	privateKey *rsa.PrivateKey
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func ParseRSAPrivateKeyPEM(
	keyID string,
	encoded []byte,
) (*SigningKey, error) {
	if !validKeyID(keyID) {
		return nil, ErrInvalidKeyID
	}

	block, remaining := pem.Decode(encoded)
	if block == nil ||
		len(strings.TrimSpace(string(remaining))) != 0 {
		return nil, ErrInvalidSigningKey
	}

	privateKey, err := parseRSAPrivateKey(block)
	if err != nil {
		return nil, err
	}

	if privateKey.N == nil ||
		privateKey.N.BitLen() < minimumRSABits ||
		privateKey.E != requiredRSAE {
		return nil, ErrInvalidSigningKey
	}

	if err := privateKey.Validate(); err != nil {
		return nil, ErrInvalidSigningKey
	}

	privateKey.Precompute()

	return &SigningKey{
		keyID:      keyID,
		privateKey: privateKey,
	}, nil

}

func (key *SigningKey) KeyID() string {
	if key == nil {
		return ""
	}

	return key.keyID
}

func (key *SigningKey) PublicJWK() JWK {
	if key == nil || key.privateKey == nil {
		return JWK{}
	}

	exponent := big.NewInt(
		int64(key.privateKey.PublicKey.E),
	).Bytes()

	return JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     key.keyID,
		Algorithm: "RS256",
		Modulus: base64.RawURLEncoding.EncodeToString(
			key.privateKey.PublicKey.N.Bytes(),
		),
		Exponent: base64.RawURLEncoding.EncodeToString(
			exponent,
		),
	}
}

func parseRSAPrivateKey(
	block *pem.Block,
) (*rsa.PrivateKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(
			block.Bytes,
		)
		if err != nil {
			return nil, ErrInvalidSigningKey
		}

		privateKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidSigningKey
		}

		return privateKey, nil

	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(
			block.Bytes,
		)
		if err != nil {
			return nil, ErrInvalidSigningKey
		}

		return privateKey, nil

	default:
		return nil, ErrInvalidSigningKey
	}
}

func validKeyID(value string) bool {
	if value == "" ||
		len(value) > maximumKeyIDLength {
		return false
	}

	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-',
			character == '_',
			character == '.':
		default:
			return false
		}
	}

	return true
}
