package auth

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
	mfaEncryptionKeyBytes = 32
	mfaAADPrefix          = "gatehouse:totp-secret:v1:"
)

var (
	ErrInvalidMFAEncryptionKey = errors.New(
		"invalid MFA encryption key",
	)
	ErrMFASecretEncryption = errors.New(
		"MFA secret encryption failed",
	)
	ErrMFASecretDecryption = errors.New(
		"MFA secret decryption failed",
	)
)

type EncryptedMFASecret struct {
	Ciphertext []byte
	Nonce      []byte
	KeyID      string
}

type MFASecretCipher interface {
	Encrypt(
		userID pgtype.UUID,
		plaintext []byte,
	) (EncryptedMFASecret, error)

	Decrypt(
		userID pgtype.UUID,
		encrypted EncryptedMFASecret,
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
		len(key) != mfaEncryptionKeyBytes {
		return nil, ErrInvalidMFAEncryptionKey
	}

	keyCopy := append([]byte(nil), key...)

	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: %v",
			ErrInvalidMFAEncryptionKey,
			err,
		)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create GCM: %v",
			ErrInvalidMFAEncryptionKey,
			err,
		)
	}

	return &AESGCMSecretCipher{
		keyID: keyID,
		aead:  aead,
	}, nil
}

func (secretCipher *AESGCMSecretCipher) Encrypt(
	userID pgtype.UUID,
	plaintext []byte,
) (EncryptedMFASecret, error) {
	if !userID.Valid || len(plaintext) == 0 {
		return EncryptedMFASecret{}, ErrMFASecretEncryption
	}

	nonce := make([]byte, secretCipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedMFASecret{}, fmt.Errorf(
			"%w: generate nonce: %v",
			ErrMFASecretEncryption,
			err,
		)
	}

	ciphertext := secretCipher.aead.Seal(
		nil,
		nonce,
		plaintext,
		mfaAdditionalData(userID),
	)

	return EncryptedMFASecret{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		KeyID:      secretCipher.keyID,
	}, nil
}

func (secretCipher *AESGCMSecretCipher) Decrypt(
	userID pgtype.UUID,
	encrypted EncryptedMFASecret,
) ([]byte, error) {
	if !userID.Valid ||
		encrypted.KeyID != secretCipher.keyID ||
		len(encrypted.Nonce) != secretCipher.aead.NonceSize() {
		return nil, ErrMFASecretDecryption
	}

	plaintext, err := secretCipher.aead.Open(
		nil,
		encrypted.Nonce,
		encrypted.Ciphertext,
		mfaAdditionalData(userID),
	)
	if err != nil {
		return nil, ErrMFASecretDecryption
	}

	return plaintext, nil
}

func mfaAdditionalData(userID pgtype.UUID) []byte {
	additionalData := make(
		[]byte,
		len(mfaAADPrefix)+len(userID.Bytes),
	)

	copy(additionalData, mfaAADPrefix)
	copy(additionalData[len(mfaAADPrefix):], userID.Bytes[:])

	return additionalData
}
