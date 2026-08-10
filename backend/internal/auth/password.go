package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      uint32 = 64 * 1024
	argonIterations  uint32 = 3
	argonParallelism uint8  = 4
	argonSaltLength         = 16
	argonKeyLength   uint32 = 32
)

var ErrInvalidPasswordHash = errors.New("invalid password hash")

type argonParameters struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		argonIterations,
		argonMemory,
		argonParallelism,
		argonKeyLength,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	parameters, salt, expectedHash, err := decodePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}

	actualHash := argon2.IDKey(
		[]byte(password),
		salt,
		parameters.iterations,
		parameters.memory,
		parameters.parallelism,
		uint32(len(expectedHash)),
	)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1, nil
}

func decodePasswordHash(encodedHash string) (argonParameters, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argonParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	versionText, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return argonParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	version, err := strconv.ParseUint(versionText, 10, 32)
	if err != nil || version != argon2.Version {
		return argonParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	parameters, err := decodeArgonParameters(parts[3])
	if err != nil {
		return argonParameters{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return argonParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) < 16 || len(hash) > 64 {
		return argonParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	return parameters, salt, hash, nil
}

func decodeArgonParameters(value string) (argonParameters, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		return argonParameters{}, ErrInvalidPasswordHash
	}

	memory, err := parseParameter(parts[0], "m=", 32)
	if err != nil || memory == 0 || memory > 256*1024 {
		return argonParameters{}, ErrInvalidPasswordHash
	}

	iterations, err := parseParameter(parts[1], "t=", 32)
	if err != nil || iterations == 0 || iterations > 10 {
		return argonParameters{}, ErrInvalidPasswordHash
	}

	parallelism, err := parseParameter(parts[2], "p=", 8)
	if err != nil || parallelism == 0 || parallelism > 16 {
		return argonParameters{}, ErrInvalidPasswordHash
	}

	return argonParameters{
		memory:      uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
	}, nil
}

func parseParameter(value, prefix string, bitSize int) (uint64, error) {
	number, ok := strings.CutPrefix(value, prefix)
	if !ok || number == "" {
		return 0, ErrInvalidPasswordHash
	}

	parsed, err := strconv.ParseUint(number, 10, bitSize)
	if err != nil {
		return 0, ErrInvalidPasswordHash
	}

	return parsed, nil
}
