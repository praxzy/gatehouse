package federation

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIDTokenClockSkew = 60 * time.Second
	maxJWTPartBytes         = 24 * 1024
	maxSubjectBytes         = 512
)

var (
	ErrInvalidIDTokenVerifier = errors.New(
		"invalid upstream ID token verifier",
	)
	ErrInvalidIDToken = errors.New(
		"invalid upstream ID token",
	)
	ErrIDTokenVerification = errors.New(
		"upstream ID token verification failed",
	)
)

type IDTokenVerifier struct {
	keys      SigningKeySource
	now       func() time.Time
	clockSkew time.Duration
}

type IDTokenVerificationInput struct {
	IDToken        string
	ExpectedIssuer string
	ClientID       string
	JWKSURI        string
	NonceHash      []byte
}

type VerifiedIdentity struct {
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type jwtHeader struct {
	Algorithm string   `json:"alg"`
	KeyID     string   `json:"kid"`
	Type      string   `json:"typ"`
	Critical  []string `json:"crit"`
}

type idTokenClaims struct {
	Issuer          string        `json:"iss"`
	Subject         string        `json:"sub"`
	Audience        audienceClaim `json:"aud"`
	Expiration      numericDate   `json:"exp"`
	IssuedAt        numericDate   `json:"iat"`
	NotBefore       numericDate   `json:"nbf"`
	Nonce           string        `json:"nonce"`
	AuthorizedParty string        `json:"azp"`
}

type audienceClaim []string

type numericDate struct {
	value int64
	set   bool
}

func NewIDTokenVerifier(
	keys SigningKeySource,
) (*IDTokenVerifier, error) {
	if keys == nil {
		return nil, ErrInvalidIDTokenVerifier
	}

	return &IDTokenVerifier{
		keys: keys,
		now: func() time.Time {
			return time.Now().UTC()
		},
		clockSkew: defaultIDTokenClockSkew,
	}, nil
}

func (verifier *IDTokenVerifier) Verify(
	ctx context.Context,
	input IDTokenVerificationInput,
) (VerifiedIdentity, error) {
	if verifier == nil ||
		verifier.keys == nil ||
		verifier.now == nil ||
		verifier.clockSkew < 0 {
		return VerifiedIdentity{},
			ErrInvalidIDTokenVerifier
	}

	if input.IDToken == "" ||
		len(input.IDToken) > maxIDTokenBytes ||
		!validSensitiveValue(
			input.ExpectedIssuer,
			2048,
		) ||
		!validSensitiveValue(
			input.ClientID,
			maxClientIDBytes,
		) ||
		len(input.NonceHash) != sha256.Size {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	parts := strings.Split(input.IDToken, ".")
	if len(parts) != 3 ||
		parts[0] == "" ||
		parts[1] == "" ||
		parts[2] == "" {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	headerPayload, err := decodeJWTPart(parts[0])
	if err != nil {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	claimsPayload, err := decodeJWTPart(parts[1])
	if err != nil {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	signature, err := decodeJWTPart(parts[2])
	if err != nil {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	if len(headerPayload) > maxJWTPartBytes ||
		len(claimsPayload) > maxJWTPartBytes {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	var header jwtHeader
	if err := decodeUniqueJSONObject(
		headerPayload,
		&header,
	); err != nil {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	if header.Algorithm != "RS256" ||
		!validSensitiveValue(
			header.KeyID,
			maxJWKKeyIDBytes,
		) ||
		len(header.Critical) != 0 ||
		(header.Type != "" &&
			!strings.EqualFold(
				header.Type,
				"JWT",
			)) {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	publicKey, err :=
		verifier.keys.GetRSASigningKey(
			ctx,
			input.JWKSURI,
			header.KeyID,
		)
	if err != nil {
		return VerifiedIdentity{},
			ErrIDTokenVerification
	}

	if publicKey == nil ||
		len(signature) != publicKey.Size() {
		return VerifiedIdentity{},
			ErrIDTokenVerification
	}

	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256(
		[]byte(signingInput),
	)

	if err := rsa.VerifyPKCS1v15(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
	); err != nil {
		return VerifiedIdentity{},
			ErrIDTokenVerification
	}

	var claims idTokenClaims
	if err := decodeUniqueJSONObject(
		claimsPayload,
		&claims,
	); err != nil {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	return verifier.validateClaims(
		input,
		claims,
	)
}

func (verifier *IDTokenVerifier) validateClaims(
	input IDTokenVerificationInput,
	claims idTokenClaims,
) (VerifiedIdentity, error) {
	if claims.Issuer != input.ExpectedIssuer ||
		!validSensitiveValue(
			claims.Subject,
			maxSubjectBytes,
		) ||
		!claims.Audience.contains(
			input.ClientID,
		) ||
		!claims.Expiration.set ||
		!claims.IssuedAt.set ||
		claims.Expiration.value <=
			claims.IssuedAt.value {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	if len(claims.Audience) > 1 &&
		claims.AuthorizedParty != input.ClientID {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	if claims.AuthorizedParty != "" &&
		claims.AuthorizedParty != input.ClientID {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	nonceHash, err := HashAuthorizationNonce(
		claims.Nonce,
	)
	if err != nil ||
		subtle.ConstantTimeCompare(
			nonceHash,
			input.NonceHash,
		) != 1 {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	now := verifier.now().UTC()
	expiresAt := time.Unix(
		claims.Expiration.value,
		0,
	).UTC()
	issuedAt := time.Unix(
		claims.IssuedAt.value,
		0,
	).UTC()

	if !now.Before(
		expiresAt.Add(verifier.clockSkew),
	) ||
		issuedAt.After(
			now.Add(verifier.clockSkew),
		) {
		return VerifiedIdentity{},
			ErrInvalidIDToken
	}

	if claims.NotBefore.set {
		notBefore := time.Unix(
			claims.NotBefore.value,
			0,
		).UTC()

		if notBefore.After(
			now.Add(verifier.clockSkew),
		) {
			return VerifiedIdentity{},
				ErrInvalidIDToken
		}
	}

	return VerifiedIdentity{
		Subject:   claims.Subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
}

func decodeJWTPart(
	value string,
) ([]byte, error) {
	decoded, err :=
		base64.RawURLEncoding.DecodeString(
			value,
		)
	if err != nil ||
		base64.RawURLEncoding.EncodeToString(
			decoded,
		) != value {
		return nil, ErrInvalidIDToken
	}

	return decoded, nil
}

func decodeUniqueJSONObject(
	payload []byte,
	target any,
) error {
	if err := rejectDuplicateJSONObjectMembers(
		payload,
	); err != nil {
		return ErrInvalidIDToken
	}

	decoder := json.NewDecoder(
		bytes.NewReader(payload),
	)

	if err := decoder.Decode(target); err != nil {
		return ErrInvalidIDToken
	}

	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidIDToken
	}

	return nil
}

func (
	audience *audienceClaim,
) UnmarshalJSON(payload []byte) error {
	if len(payload) == 0 {
		return ErrInvalidIDToken
	}

	var values []string

	if payload[0] == '"' {
		var single string
		if err := json.Unmarshal(
			payload,
			&single,
		); err != nil {
			return ErrInvalidIDToken
		}

		values = []string{single}
	} else {
		if err := json.Unmarshal(
			payload,
			&values,
		); err != nil {
			return ErrInvalidIDToken
		}
	}

	if len(values) == 0 {
		return ErrInvalidIDToken
	}

	seen := make(map[string]struct{})
	for _, value := range values {
		if !validSensitiveValue(
			value,
			maxClientIDBytes,
		) {
			return ErrInvalidIDToken
		}

		if _, exists := seen[value]; exists {
			return ErrInvalidIDToken
		}
		seen[value] = struct{}{}
	}

	*audience = append(
		(*audience)[:0],
		values...,
	)

	return nil
}

func (
	audience audienceClaim,
) contains(expected string) bool {
	for _, value := range audience {
		if value == expected {
			return true
		}
	}

	return false
}

func (
	date *numericDate,
) UnmarshalJSON(payload []byte) error {
	if len(payload) == 0 ||
		payload[0] == '"' ||
		bytes.Equal(payload, []byte("null")) {
		return ErrInvalidIDToken
	}

	value, err := strconv.ParseInt(
		string(payload),
		10,
		64,
	)
	if err != nil || value <= 0 {
		return ErrInvalidIDToken
	}

	date.value = value
	date.set = true

	return nil
}
