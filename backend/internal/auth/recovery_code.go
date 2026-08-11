package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	recoveryCodeBytes      = 12
	recoveryCodeCharacters = 20
	maxRecoveryCodeCount   = 100
)

var ErrInvalidRecoveryCode = errors.New("invalid recovery code")

var recoveryCodeBase32 = base32.StdEncoding.WithPadding(
	base32.NoPadding,
)

type GeneratedRecoveryCode struct {
	Code string
	Hash []byte
}

func GenerateRecoveryCodes(
	count int,
) ([]GeneratedRecoveryCode, error) {
	if count <= 0 || count > maxRecoveryCodeCount {
		return nil, ErrInvalidRecoveryCode
	}

	codes := make([]GeneratedRecoveryCode, 0, count)
	seen := make(map[string]struct{}, count)

	for len(codes) < count {
		randomBytes := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(randomBytes); err != nil {
			return nil, fmt.Errorf(
				"generate recovery code: %w",
				err,
			)
		}

		normalized := recoveryCodeBase32.EncodeToString(
			randomBytes,
		)
		if _, exists := seen[normalized]; exists {
			continue
		}

		seen[normalized] = struct{}{}
		digest := sha256.Sum256([]byte(normalized))

		codes = append(codes, GeneratedRecoveryCode{
			Code: formatRecoveryCode(normalized),
			Hash: append([]byte(nil), digest[:]...),
		})
	}

	return codes, nil
}

func HashRecoveryCode(code string) ([]byte, error) {
	normalized, err := normalizeRecoveryCode(code)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256([]byte(normalized))
	return digest[:], nil
}

func normalizeRecoveryCode(code string) (string, error) {
	normalized := strings.Map(func(character rune) rune {
		if character == '-' || unicode.IsSpace(character) {
			return -1
		}

		return unicode.ToUpper(character)
	}, code)

	if len(normalized) != recoveryCodeCharacters {
		return "", ErrInvalidRecoveryCode
	}

	for _, character := range normalized {
		validLetter := character >= 'A' && character <= 'Z'
		validDigit := character >= '2' && character <= '7'

		if !validLetter && !validDigit {
			return "", ErrInvalidRecoveryCode
		}
	}

	return normalized, nil
}

func formatRecoveryCode(normalized string) string {
	groups := make([]string, 0, 4)

	for start := 0; start < len(normalized); start += 5 {
		end := start + 5
		groups = append(groups, normalized[start:end])
	}

	return strings.Join(groups, "-")
}
