package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

var (
	ErrInvalidIDTokenClaims = errors.New(
		"invalid ID token claims",
	)
	ErrIDTokenSigning = errors.New(
		"sign ID token",
	)
)

type IDTokenClaims struct {
	Issuer             string   `json:"iss"`
	Subject            string   `json:"sub"`
	Audience           string   `json:"aud"`
	ExpiresAt          int64    `json:"exp"`
	IssuedAt           int64    `json:"iat"`
	AuthenticationTime int64    `json:"auth_time,omitempty"`
	Nonce              string   `json:"nonce,omitempty"`
	Name               string   `json:"name"`
	Email              string   `json:"email"`
	EmailVerified      bool     `json:"email_verified"`
	Roles              []string `json:"roles"`
}

type idTokenHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

func (key *SigningKey) SignIDToken(
	claims IDTokenClaims,
) (string, error) {
	if key == nil || key.privateKey == nil {
		return "", ErrInvalidSigningKey
	}

	if err := validateIDTokenClaims(claims); err != nil {
		return "", err
	}

	headerJSON, err := json.Marshal(idTokenHeader{
		Algorithm: "RS256",
		Type:      "JWT",
		KeyID:     key.keyID,
	})
	if err != nil {
		return "", ErrIDTokenSigning
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", ErrIDTokenSigning
	}

	encodedHeader :=
		base64.RawURLEncoding.EncodeToString(
			headerJSON,
		)
	encodedClaims :=
		base64.RawURLEncoding.EncodeToString(
			claimsJSON,
		)

	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		key.privateKey,
		crypto.SHA256,
		digest[:],
	)
	if err != nil {
		return "", ErrIDTokenSigning
	}

	return signingInput + "." +
		base64.RawURLEncoding.EncodeToString(
			signature,
		), nil
}

func validateIDTokenClaims(
	claims IDTokenClaims,
) error {
	if claims.Issuer == "" ||
		claims.Issuer !=
			strings.TrimSpace(claims.Issuer) ||
		claims.Subject == "" ||
		claims.Subject !=
			strings.TrimSpace(claims.Subject) ||
		claims.Audience == "" ||
		claims.Audience !=
			strings.TrimSpace(claims.Audience) ||
		claims.IssuedAt <= 0 ||
		claims.ExpiresAt <= claims.IssuedAt ||
		claims.AuthenticationTime < 0 ||
		claims.Name == "" ||
		claims.Name != strings.TrimSpace(claims.Name) ||
		claims.Email == "" ||
		claims.Email != strings.TrimSpace(claims.Email) ||
		!claims.EmailVerified ||
		len(claims.Roles) == 0 ||
		!validRoleClaims(claims.Roles) {
		return ErrInvalidIDTokenClaims
	}

	return nil
}

func validRoleClaims(roles []string) bool {
	seen := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		if role == "" ||
			role != strings.TrimSpace(role) {
			return false
		}

		if _, exists := seen[role]; exists {
			return false
		}
		seen[role] = struct{}{}
	}

	return true
}
