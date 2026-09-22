package federation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type fakeSigningKeySource struct {
	key     *rsa.PublicKey
	err     error
	jwksURI string
	keyID   string
	calls   int
}

func (fake *fakeSigningKeySource) GetRSASigningKey(
	_ context.Context,
	jwksURI string,
	keyID string,
) (*rsa.PublicKey, error) {
	fake.calls++
	fake.jwksURI = jwksURI
	fake.keyID = keyID

	return fake.key, fake.err
}

func signFederationTestToken(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	header map[string]any,
	claims map[string]any,
) string {
	t.Helper()

	headerPayload, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	claimsPayload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	encodedHeader :=
		base64.RawURLEncoding.EncodeToString(
			headerPayload,
		)
	encodedClaims :=
		base64.RawURLEncoding.EncodeToString(
			claimsPayload,
		)

	signingInput :=
		encodedHeader + "." + encodedClaims
	digest := sha256.Sum256(
		[]byte(signingInput),
	)

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		digest[:],
	)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return signingInput + "." +
		base64.RawURLEncoding.EncodeToString(
			signature,
		)
}

func validIDTokenClaims(
	now time.Time,
	nonce string,
) map[string]any {
	return map[string]any{
		"iss":   "https://identity.example.com",
		"sub":   "external-user-123",
		"aud":   "gatehouse-client",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nonce": nonce,
	}
}

func TestIDTokenVerifierAcceptsValidToken(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	keys := &fakeSigningKeySource{
		key: &privateKey.PublicKey,
	}

	verifier, err := NewIDTokenVerifier(keys)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	now := time.Date(
		2026,
		time.September,
		22,
		12,
		0,
		0,
		0,
		time.UTC,
	)
	verifier.now = func() time.Time {
		return now
	}

	artifacts, err :=
		GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf("generate artifacts: %v", err)
	}

	token := signFederationTestToken(
		t,
		privateKey,
		map[string]any{
			"alg": "RS256",
			"kid": "provider-key-v1",
			"typ": "JWT",
		},
		validIDTokenClaims(
			now,
			artifacts.Nonce,
		),
	)

	result, err := verifier.Verify(
		t.Context(),
		IDTokenVerificationInput{
			IDToken:        token,
			ExpectedIssuer: "https://identity.example.com",
			ClientID:       "gatehouse-client",
			JWKSURI:        "https://identity.example.com/jwks",
			NonceHash:      artifacts.NonceHash,
		},
	)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}

	if result.Subject != "external-user-123" ||
		!result.IssuedAt.Equal(
			now.Add(-time.Minute),
		) ||
		!result.ExpiresAt.Equal(
			now.Add(5*time.Minute),
		) {
		t.Fatalf(
			"unexpected identity: %+v",
			result,
		)
	}

	if keys.calls != 1 ||
		keys.keyID != "provider-key-v1" ||
		keys.jwksURI !=
			"https://identity.example.com/jwks" {
		t.Fatalf(
			"unexpected key lookup: %+v",
			keys,
		)
	}
}

func TestIDTokenVerifierRejectsInvalidClaims(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	now := time.Date(
		2026,
		time.September,
		22,
		12,
		0,
		0,
		0,
		time.UTC,
	)

	artifacts, err :=
		GenerateAuthorizationArtifacts()
	if err != nil {
		t.Fatalf("generate artifacts: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "wrong issuer",
			mutate: func(claims map[string]any) {
				claims["iss"] =
					"https://attacker.example.com"
			},
		},
		{
			name: "wrong audience",
			mutate: func(claims map[string]any) {
				claims["aud"] =
					"different-client"
			},
		},
		{
			name: "multiple audiences without azp",
			mutate: func(claims map[string]any) {
				claims["aud"] = []string{
					"gatehouse-client",
					"another-client",
				}
			},
		},
		{
			name: "wrong authorized party",
			mutate: func(claims map[string]any) {
				claims["aud"] = []string{
					"gatehouse-client",
					"another-client",
				}
				claims["azp"] =
					"another-client"
			},
		},
		{
			name: "expired",
			mutate: func(claims map[string]any) {
				claims["exp"] =
					now.Add(-2 * time.Minute).Unix()
			},
		},
		{
			name: "missing expiration",
			mutate: func(claims map[string]any) {
				delete(claims, "exp")
			},
		},
		{
			name: "future issued-at",
			mutate: func(claims map[string]any) {
				claims["iat"] =
					now.Add(2 * time.Minute).Unix()
			},
		},
		{
			name: "missing issued-at",
			mutate: func(claims map[string]any) {
				delete(claims, "iat")
			},
		},
		{
			name: "future not-before",
			mutate: func(claims map[string]any) {
				claims["nbf"] =
					now.Add(2 * time.Minute).Unix()
			},
		},
		{
			name: "wrong nonce",
			mutate: func(claims map[string]any) {
				other, err :=
					GenerateAuthorizationArtifacts()
				if err != nil {
					panic(err)
				}
				claims["nonce"] = other.Nonce
			},
		},
		{
			name: "missing nonce",
			mutate: func(claims map[string]any) {
				delete(claims, "nonce")
			},
		},
		{
			name: "missing subject",
			mutate: func(claims map[string]any) {
				delete(claims, "sub")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := validIDTokenClaims(
				now,
				artifacts.Nonce,
			)
			test.mutate(claims)

			token := signFederationTestToken(
				t,
				privateKey,
				map[string]any{
					"alg": "RS256",
					"kid": "provider-key-v1",
				},
				claims,
			)

			keys := &fakeSigningKeySource{
				key: &privateKey.PublicKey,
			}
			verifier, err :=
				NewIDTokenVerifier(keys)
			if err != nil {
				t.Fatalf(
					"create verifier: %v",
					err,
				)
			}
			verifier.now = func() time.Time {
				return now
			}

			_, err = verifier.Verify(
				t.Context(),
				IDTokenVerificationInput{
					IDToken:        token,
					ExpectedIssuer: "https://identity.example.com",
					ClientID:       "gatehouse-client",
					JWKSURI:        "https://identity.example.com/jwks",
					NonceHash:      artifacts.NonceHash,
				},
			)
			if !errors.Is(
				err,
				ErrInvalidIDToken,
			) {
				t.Fatalf(
					"expected invalid token, got %v",
					err,
				)
			}
		})
	}
}

func TestIDTokenVerifierRejectsInvalidHeader(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	now := time.Now().UTC()
	artifacts, _ :=
		GenerateAuthorizationArtifacts()

	tests := []struct {
		name   string
		header map[string]any
	}{
		{
			name: "wrong algorithm",
			header: map[string]any{
				"alg": "HS256",
				"kid": "key",
			},
		},
		{
			name: "missing key ID",
			header: map[string]any{
				"alg": "RS256",
			},
		},
		{
			name: "critical extensions",
			header: map[string]any{
				"alg":  "RS256",
				"kid":  "key",
				"crit": []string{"custom"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signFederationTestToken(
				t,
				privateKey,
				test.header,
				validIDTokenClaims(
					now,
					artifacts.Nonce,
				),
			)

			keys := &fakeSigningKeySource{
				key: &privateKey.PublicKey,
			}
			verifier, _ :=
				NewIDTokenVerifier(keys)
			verifier.now = func() time.Time {
				return now
			}

			_, err := verifier.Verify(
				t.Context(),
				IDTokenVerificationInput{
					IDToken:        token,
					ExpectedIssuer: "https://identity.example.com",
					ClientID:       "gatehouse-client",
					JWKSURI:        "https://identity.example.com/jwks",
					NonceHash:      artifacts.NonceHash,
				},
			)
			if !errors.Is(
				err,
				ErrInvalidIDToken,
			) {
				t.Fatalf(
					"expected invalid token, got %v",
					err,
				)
			}

			if keys.calls != 0 {
				t.Fatal(
					"invalid header triggered key lookup",
				)
			}
		})
	}
}

func TestIDTokenVerifierRejectsInvalidSignature(
	t *testing.T,
) {
	signingKey := generateJWKSTestKey(
		t,
		2048,
	)
	differentKey := generateJWKSTestKey(
		t,
		2048,
	)
	now := time.Now().UTC()
	artifacts, _ :=
		GenerateAuthorizationArtifacts()

	token := signFederationTestToken(
		t,
		signingKey,
		map[string]any{
			"alg": "RS256",
			"kid": "key",
		},
		validIDTokenClaims(
			now,
			artifacts.Nonce,
		),
	)

	verifier, _ := NewIDTokenVerifier(
		&fakeSigningKeySource{
			key: &differentKey.PublicKey,
		},
	)
	verifier.now = func() time.Time {
		return now
	}

	_, err := verifier.Verify(
		t.Context(),
		IDTokenVerificationInput{
			IDToken:        token,
			ExpectedIssuer: "https://identity.example.com",
			ClientID:       "gatehouse-client",
			JWKSURI:        "https://identity.example.com/jwks",
			NonceHash:      artifacts.NonceHash,
		},
	)
	if !errors.Is(
		err,
		ErrIDTokenVerification,
	) {
		t.Fatalf(
			"expected signature failure, got %v",
			err,
		)
	}
}

func TestIDTokenVerifierAcceptsMultipleAudienceWithAZP(
	t *testing.T,
) {
	privateKey := generateJWKSTestKey(
		t,
		2048,
	)
	now := time.Now().UTC()
	artifacts, _ :=
		GenerateAuthorizationArtifacts()

	claims := validIDTokenClaims(
		now,
		artifacts.Nonce,
	)
	claims["aud"] = []string{
		"gatehouse-client",
		"another-client",
	}
	claims["azp"] = "gatehouse-client"

	token := signFederationTestToken(
		t,
		privateKey,
		map[string]any{
			"alg": "RS256",
			"kid": "key",
		},
		claims,
	)

	verifier, _ := NewIDTokenVerifier(
		&fakeSigningKeySource{
			key: &privateKey.PublicKey,
		},
	)
	verifier.now = func() time.Time {
		return now
	}

	if _, err := verifier.Verify(
		t.Context(),
		IDTokenVerificationInput{
			IDToken:        token,
			ExpectedIssuer: "https://identity.example.com",
			ClientID:       "gatehouse-client",
			JWKSURI:        "https://identity.example.com/jwks",
			NonceHash:      artifacts.NonceHash,
		},
	); err != nil {
		t.Fatalf(
			"valid multi-audience token rejected: %v",
			err,
		)
	}
}

func TestIDTokenVerifierRejectsInvalidConfiguration(
	t *testing.T,
) {
	if _, err := NewIDTokenVerifier(nil); !errors.Is(
		err,
		ErrInvalidIDTokenVerifier,
	) {
		t.Fatalf(
			"expected invalid verifier error, got %v",
			err,
		)
	}
}

var _ SigningKeySource = (*fakeSigningKeySource)(nil)
