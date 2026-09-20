package federation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	federationEncryptionKeyBytes = 32
	maxFederationSecretBytes     = 4096
	federationAADPrefix          = "gatehouse:upstream-oidc:v1:"
)

var (
	ErrInvalidEncryptionKey = errors.New(
		"invalid federation encryption key",
	)
	ErrSecretEncryption = errors.New(
		"federation secret encryption failed",
	)
	ErrSecretDecryption = errors.New(
		"federation secret decryption failed",
	)
)

type SecretPurpose string

const (
	SecretPurposeClientSecret SecretPurpose = "client_secret"
	SecretPurposePKCEVerifier SecretPurpose = "pkce_verifier"
)

type EncryptedSecret struct {
	Ciphertext []byte
	Nonce      []byte
	KeyID      string
}

type SecretCipher interface {
	Encrypt(
		tenantID pgtype.UUID,
		purpose SecretPurpose,
		plaintext []byte,
	) (EncryptedSecret, error)

	Decrypt(
		tenantID pgtype.UUID,
		purpose SecretPurpose,
		encrypted EncryptedSecret,
	) ([]byte, error)
}

type AESGCMSecretCipher struct {
	keyID string
	aead  cipher.AEAD
}

func NewAESGCMSecretCipher(
	keyID string,
	key []byte,
) (*AESGCMSecretCipher, error) {
	if keyID == "" ||
		keyID != strings.TrimSpace(keyID) ||
		!utf8.ValidString(keyID) ||
		utf8.RuneCountInString(keyID) > 100 ||
		len(key) != federationEncryptionKeyBytes {
		return nil, ErrInvalidEncryptionKey
	}

	keyCopy := append([]byte(nil), key...)

	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrInvalidEncryptionKey,
			err,
		)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create GCM: %v",
			ErrInvalidEncryptionKey,
			err,
		)
	}

	return &AESGCMSecretCipher{
		keyID: keyID,
		aead:  aead,
	}, nil
}

func (secretCipher *AESGCMSecretCipher) Encrypt(
	tenantID pgtype.UUID,
	purpose SecretPurpose,
	plaintext []byte,
) (EncryptedSecret, error) {
	if secretCipher == nil ||
		secretCipher.aead == nil ||
		!tenantID.Valid ||
		!validSecretPurpose(purpose) ||
		len(plaintext) == 0 ||
		len(plaintext) > maxFederationSecretBytes {
		return EncryptedSecret{}, ErrSecretEncryption
	}

	nonce := make([]byte, secretCipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedSecret{}, fmt.Errorf(
			"%w: generate nonce: %v",
			ErrSecretEncryption,
			err,
		)
	}

	ciphertext := secretCipher.aead.Seal(
		nil,
		nonce,
		plaintext,
		federationAdditionalData(tenantID, purpose),
	)

	return EncryptedSecret{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		KeyID:      secretCipher.keyID,
	}, nil
}

func (secretCipher *AESGCMSecretCipher) Decrypt(
	tenantID pgtype.UUID,
	purpose SecretPurpose,
	encrypted EncryptedSecret,
) ([]byte, error) {
	if secretCipher == nil ||
		secretCipher.aead == nil ||
		!tenantID.Valid ||
		!validSecretPurpose(purpose) ||
		encrypted.KeyID != secretCipher.keyID ||
		len(encrypted.Nonce) != secretCipher.aead.NonceSize() ||
		len(encrypted.Ciphertext) < secretCipher.aead.Overhead() {
		return nil, ErrSecretDecryption
	}

	plaintext, err := secretCipher.aead.Open(
		nil,
		encrypted.Nonce,
		encrypted.Ciphertext,
		federationAdditionalData(tenantID, purpose),
	)
	if err != nil {
		return nil, ErrSecretDecryption
	}

	if len(plaintext) == 0 ||
		len(plaintext) > maxFederationSecretBytes {
		return nil, ErrSecretDecryption
	}

	return plaintext, nil
}

func validSecretPurpose(purpose SecretPurpose) bool {
	switch purpose {
	case SecretPurposeClientSecret,
		SecretPurposePKCEVerifier:
		return true
	default:
		return false
	}
}

func federationAdditionalData(
	tenantID pgtype.UUID,
	purpose SecretPurpose,
) []byte {
	additionalData := make(
		[]byte,
		0,
		len(federationAADPrefix)+len(purpose)+1+len(tenantID.Bytes),
	)

	additionalData = append(
		additionalData,
		federationAADPrefix...,
	)
	additionalData = append(
		additionalData,
		string(purpose)...,
	)
	additionalData = append(additionalData, 0)
	additionalData = append(
		additionalData,
		tenantID.Bytes[:]...,
	)

	return additionalData
}
