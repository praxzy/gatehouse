package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	totpSecretBytes = 20
	totpDigits      = 6
	totpPeriod      = 30
)

var (
	ErrInvalidTOTPSecret = errors.New("invalid TOTP secret")
	ErrInvalidTOTPUri    = errors.New("invalid TOTP provisioning data")
)

var totpBase32 = base32.StdEncoding.WithPadding(
	base32.NoPadding,
)

func GenerateTOTPSecret() ([]byte, error) {
	secret := make([]byte, totpSecretBytes)

	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}

	return secret, nil
}

func TOTPProvisioningURI(
	issuer string,
	account string,
	secret []byte,
) (string, error) {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)

	if issuer == "" ||
		account == "" ||
		len(secret) < totpSecretBytes {
		return "", ErrInvalidTOTPUri
	}

	uri := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "/" + issuer + ":" + account,
	}

	query := uri.Query()
	query.Set("secret", totpBase32.EncodeToString(secret))
	query.Set("issuer", issuer)
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(totpDigits))
	query.Set("period", strconv.Itoa(totpPeriod))
	uri.RawQuery = query.Encode()

	return uri.String(), nil
}

func GenerateTOTPCode(
	secret []byte,
	at time.Time,
) (string, error) {
	if len(secret) < totpSecretBytes || at.Unix() < 0 {
		return "", ErrInvalidTOTPSecret
	}

	return generateTOTPCodeForStep(
		secret,
		at.Unix()/totpPeriod,
	), nil
}

func MatchTOTPCode(
	secret []byte,
	code string,
	at time.Time,
) (int64, bool) {
	if len(secret) < totpSecretBytes ||
		at.Unix() < 0 ||
		!validTOTPCode(code) {
		return 0, false
	}

	currentStep := at.Unix() / totpPeriod

	for _, offset := range []int64{0, -1, 1} {
		candidateStep := currentStep + offset
		if candidateStep < 0 {
			continue
		}

		expected := generateTOTPCodeForStep(
			secret,
			candidateStep,
		)

		if subtle.ConstantTimeCompare(
			[]byte(expected),
			[]byte(code),
		) == 1 {
			return candidateStep, true
		}
	}

	return 0, false
}

func generateTOTPCodeForStep(
	secret []byte,
	step int64,
) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	hash := hmac.New(sha1.New, secret)
	_, _ = hash.Write(counter[:])
	digest := hash.Sum(nil)

	offset := digest[len(digest)-1] & 0x0f

	value := (uint32(digest[offset])&0x7f)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])

	code := value % 1_000_000
	return fmt.Sprintf("%06d", code)
}

func validTOTPCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}

	for _, character := range code {
		if character < '0' || character > '9' {
			return false
		}
	}

	return true
}
