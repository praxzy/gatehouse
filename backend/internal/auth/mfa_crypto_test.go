package auth

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestAESGCMSecretCipherRoundTrip(t *testing.T) {
	secretCipher := newTestMFASecretCipher(t, 1)
	userID := testMFAUserID(1)
	plaintext := []byte("01234567890123456789")

	encrypted, err := secretCipher.Encrypt(userID, plaintext)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	if bytes.Equal(encrypted.Ciphertext, plaintext) {
		t.Fatal("ciphertext exposed plaintext")
	}

	decrypted, err := secretCipher.Decrypt(userID, encrypted)
	if err != nil {
		t.Fatalf("decrypt secret: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("decrypted secret did not match plaintext")
	}
}

func TestAESGCMSecretCipherUsesUniqueNonce(t *testing.T) {
	secretCipher := newTestMFASecretCipher(t, 1)
	userID := testMFAUserID(1)
	plaintext := []byte("01234567890123456789")

	first, err := secretCipher.Encrypt(userID, plaintext)
	if err != nil {
		t.Fatalf("encrypt first secret: %v", err)
	}

	second, err := secretCipher.Encrypt(userID, plaintext)
	if err != nil {
		t.Fatalf("encrypt second secret: %v", err)
	}

	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("expected unique AES-GCM nonces")
	}

	if bytes.Equal(first.Ciphertext, second.Ciphertext) {
		t.Fatal("expected distinct ciphertext")
	}
}

func TestAESGCMSecretCipherBindsUserID(t *testing.T) {
	secretCipher := newTestMFASecretCipher(t, 1)

	encrypted, err := secretCipher.Encrypt(
		testMFAUserID(1),
		[]byte("01234567890123456789"),
	)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	_, err = secretCipher.Decrypt(testMFAUserID(2), encrypted)
	if !errors.Is(err, ErrMFASecretDecryption) {
		t.Fatalf(
			"expected ErrMFASecretDecryption, got %v",
			err,
		)
	}
}

func newTestMFASecretCipher(
	t *testing.T,
	keyByte byte,
) *AESGCMSecretCipher {
	t.Helper()

	key := bytes.Repeat([]byte{keyByte}, mfaEncryptionKeyBytes)

	secretCipher, err := NewAESGCMSecretCipher("test-key-v1", key)
	if err != nil {
		t.Fatalf("create test cipher: %v", err)
	}

	return secretCipher
}

func testMFAUserID(lastByte byte) pgtype.UUID {
	var value [16]byte
	value[15] = lastByte

	return pgtype.UUID{
		Bytes: value,
		Valid: true,
	}
}
