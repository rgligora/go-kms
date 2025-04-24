package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// saltSize is the length of the salt in bytes (>= 128 bits).
	saltSize = 16
	// pbkdf2Iter is the PBKDF2 iteration count (recommended ~600k for SHA-256).
	pbkdf2Iter = 600_000
	// pbkdf2KeyLen is the length of the derived master key (256 bits for AES-256).
	pbkdf2KeyLen = 32
	// aesGCMNonceSize is the nonce length for AES-GCM (12 bytes recommended).
	aesGCMNonceSize = 12
)

// GenerateSalt returns a new random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// DeriveMasterKey derives a 256-bit key from the given passphrase and salt
// using PBKDF2 with HMAC-SHA-256.
func DeriveMasterKey(passphrase, salt []byte) []byte {
	return pbkdf2.Key(passphrase, salt, pbkdf2Iter, pbkdf2KeyLen, sha256.New)
}

// WrapKey encrypts (wraps) the plaintext DEK using AES-256-GCM under the master key.
// Output format: nonce || ciphertext.
func WrapKey(masterKey, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, dek, nil)
	return append(nonce, ciphertext...), nil
}

// UnwrapKey decrypts the wrapped DEK blob (nonce || ciphertext) using AES-256-GCM under the master key.
func UnwrapKey(masterKey, wrapped []byte) ([]byte, error) {
	if len(wrapped) < aesGCMNonceSize {
		return nil, errors.New("wrapped key too short")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := wrapped[:aesGCMNonceSize]
	ciphertext := wrapped[aesGCMNonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Zeroize overwrites the contents of the byte slice with zeros.
// Use to clear sensitive buffers immediately after use.
func Zeroize(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
