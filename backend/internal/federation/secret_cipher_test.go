package federation

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func federationTestUUID(value byte) pgtype.UUID {
	var id [16]byte
	id[15] = value

	return pgtype.UUID{
		Bytes: id,
		Valid: true,
	}
}

func newFederationTestCipher(
	t *testing.T,
	keyID string,
	keyByte byte,
) *AESGCMSecretCipher {
	t.Helper()

	secretCipher, err := NewAESGCMSecretCipher(
		keyID,
		bytes.Repeat([]byte{keyByte}, federationEncryptionKeyBytes),
	)
	if err != nil {
		t.Fatalf("create secret cipher: %v", err)
	}

	return secretCipher
}

func cloneEncryptedSecret(
	encrypted EncryptedSecret,
) EncryptedSecret {
	return EncryptedSecret{
		Ciphertext: append(
			[]byte(nil),
			encrypted.Ciphertext...,
		),
		Nonce: append(
			[]byte(nil),
			encrypted.Nonce...,
		),
		KeyID: encrypted.KeyID,
	}
}

func TestFederationSecretCipherRoundTrip(t *testing.T) {
	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		1,
	)
	tenantID := federationTestUUID(1)

	tests := []struct {
		name      string
		purpose   SecretPurpose
		plaintext []byte
	}{
		{
			name:      "client secret",
			purpose:   SecretPurposeClientSecret,
			plaintext: []byte("upstream-client-secret"),
		},
		{
			name:      "PKCE verifier",
			purpose:   SecretPurposePKCEVerifier,
			plaintext: []byte(strings.Repeat("v", 64)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypted, err := secretCipher.Encrypt(
				tenantID,
				test.purpose,
				test.plaintext,
			)
			if err != nil {
				t.Fatalf("encrypt secret: %v", err)
			}

			if encrypted.KeyID != "federation-key-v1" {
				t.Fatalf(
					"unexpected key ID: %q",
					encrypted.KeyID,
				)
			}

			if len(encrypted.Nonce) != 12 {
				t.Fatalf(
					"unexpected nonce length: %d",
					len(encrypted.Nonce),
				)
			}

			if bytes.Equal(
				encrypted.Ciphertext,
				test.plaintext,
			) {
				t.Fatal("ciphertext contains plaintext")
			}

			decrypted, err := secretCipher.Decrypt(
				tenantID,
				test.purpose,
				encrypted,
			)
			if err != nil {
				t.Fatalf("decrypt secret: %v", err)
			}

			if !bytes.Equal(decrypted, test.plaintext) {
				t.Fatalf(
					"unexpected plaintext: %q",
					decrypted,
				)
			}
		})
	}
}

func TestFederationSecretCipherUsesRandomNonces(
	t *testing.T,
) {
	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		2,
	)
	tenantID := federationTestUUID(2)
	plaintext := []byte("same-client-secret")

	first, err := secretCipher.Encrypt(
		tenantID,
		SecretPurposeClientSecret,
		plaintext,
	)
	if err != nil {
		t.Fatalf("encrypt first secret: %v", err)
	}

	second, err := secretCipher.Encrypt(
		tenantID,
		SecretPurposeClientSecret,
		plaintext,
	)
	if err != nil {
		t.Fatalf("encrypt second secret: %v", err)
	}

	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("encryption reused a nonce")
	}

	if bytes.Equal(
		first.Ciphertext,
		second.Ciphertext,
	) {
		t.Fatal("repeated encryption produced identical ciphertext")
	}
}

func TestFederationSecretCipherRejectsWrongBinding(
	t *testing.T,
) {
	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		3,
	)
	tenantID := federationTestUUID(3)

	encrypted, err := secretCipher.Encrypt(
		tenantID,
		SecretPurposeClientSecret,
		[]byte("upstream-client-secret"),
	)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	tests := []struct {
		name      string
		tenantID  pgtype.UUID
		purpose   SecretPurpose
		encrypted EncryptedSecret
	}{
		{
			name:      "wrong tenant",
			tenantID:  federationTestUUID(4),
			purpose:   SecretPurposeClientSecret,
			encrypted: cloneEncryptedSecret(encrypted),
		},
		{
			name:      "wrong purpose",
			tenantID:  tenantID,
			purpose:   SecretPurposePKCEVerifier,
			encrypted: cloneEncryptedSecret(encrypted),
		},
		{
			name:     "wrong key ID",
			tenantID: tenantID,
			purpose:  SecretPurposeClientSecret,
			encrypted: func() EncryptedSecret {
				value := cloneEncryptedSecret(encrypted)
				value.KeyID = "different-key"
				return value
			}(),
		},
		{
			name:     "modified ciphertext",
			tenantID: tenantID,
			purpose:  SecretPurposeClientSecret,
			encrypted: func() EncryptedSecret {
				value := cloneEncryptedSecret(encrypted)
				value.Ciphertext[0] ^= 1
				return value
			}(),
		},
		{
			name:     "modified nonce",
			tenantID: tenantID,
			purpose:  SecretPurposeClientSecret,
			encrypted: func() EncryptedSecret {
				value := cloneEncryptedSecret(encrypted)
				value.Nonce[0] ^= 1
				return value
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := secretCipher.Decrypt(
				test.tenantID,
				test.purpose,
				test.encrypted,
			)
			if !errors.Is(err, ErrSecretDecryption) {
				t.Fatalf(
					"expected decryption error, got %v",
					err,
				)
			}
		})
	}
}

func TestFederationSecretCipherRejectsWrongKey(
	t *testing.T,
) {
	encryptor := newFederationTestCipher(
		t,
		"federation-key-v1",
		5,
	)
	decryptor := newFederationTestCipher(
		t,
		"federation-key-v1",
		6,
	)
	tenantID := federationTestUUID(5)

	encrypted, err := encryptor.Encrypt(
		tenantID,
		SecretPurposeClientSecret,
		[]byte("upstream-client-secret"),
	)
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}

	_, err = decryptor.Decrypt(
		tenantID,
		SecretPurposeClientSecret,
		encrypted,
	)
	if !errors.Is(err, ErrSecretDecryption) {
		t.Fatalf(
			"expected wrong-key rejection, got %v",
			err,
		)
	}
}

func TestFederationSecretCipherRejectsInvalidInput(
	t *testing.T,
) {
	secretCipher := newFederationTestCipher(
		t,
		"federation-key-v1",
		7,
	)
	tenantID := federationTestUUID(7)

	tests := []struct {
		name      string
		tenantID  pgtype.UUID
		purpose   SecretPurpose
		plaintext []byte
	}{
		{
			name:      "missing tenant",
			purpose:   SecretPurposeClientSecret,
			plaintext: []byte("secret"),
		},
		{
			name:      "unknown purpose",
			tenantID:  tenantID,
			purpose:   SecretPurpose("unknown"),
			plaintext: []byte("secret"),
		},
		{
			name:     "empty plaintext",
			tenantID: tenantID,
			purpose:  SecretPurposeClientSecret,
		},
		{
			name:     "oversized plaintext",
			tenantID: tenantID,
			purpose:  SecretPurposeClientSecret,
			plaintext: make(
				[]byte,
				maxFederationSecretBytes+1,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := secretCipher.Encrypt(
				test.tenantID,
				test.purpose,
				test.plaintext,
			)
			if !errors.Is(err, ErrSecretEncryption) {
				t.Fatalf(
					"expected encryption error, got %v",
					err,
				)
			}
		})
	}
}

func TestFederationSecretCipherRejectsInvalidConfiguration(
	t *testing.T,
) {
	tests := []struct {
		name  string
		keyID string
		key   []byte
	}{
		{
			name: "missing key ID",
			key: bytes.Repeat(
				[]byte{1},
				federationEncryptionKeyBytes,
			),
		},
		{
			name:  "key ID has whitespace",
			keyID: " federation-key-v1 ",
			key: bytes.Repeat(
				[]byte{1},
				federationEncryptionKeyBytes,
			),
		},
		{
			name:  "key ID too long",
			keyID: strings.Repeat("k", 101),
			key: bytes.Repeat(
				[]byte{1},
				federationEncryptionKeyBytes,
			),
		},
		{
			name:  "invalid UTF-8 key ID",
			keyID: string([]byte{0xff}),
			key: bytes.Repeat(
				[]byte{1},
				federationEncryptionKeyBytes,
			),
		},
		{
			name:  "short key",
			keyID: "federation-key-v1",
			key: bytes.Repeat(
				[]byte{1},
				federationEncryptionKeyBytes-1,
			),
		},
		{
			name:  "long key",
			keyID: "federation-key-v1",
			key: bytes.Repeat(
				[]byte{1},
				federationEncryptionKeyBytes+1,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewAESGCMSecretCipher(
				test.keyID,
				test.key,
			)
			if !errors.Is(
				err,
				ErrInvalidEncryptionKey,
			) {
				t.Fatalf(
					"expected key error, got %v",
					err,
				)
			}
		})
	}
}
