package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/store"
)

// KMSService provides core key management operations.
type KMSService struct {
	store     store.SecretStore
	masterKey []byte
}

// NewKMSService constructs a new KMSService.
func NewKMSService(s store.SecretStore, masterKey []byte) *KMSService {
	return &KMSService{store: s, masterKey: masterKey}
}

func (k *KMSService) GetWrappedKey(keyID string) ([]byte, error) {
	return k.store.LoadWrappedKey(keyID)
}

func (k *KMSService) ListKeyIds() ([]string, error) {
	return k.store.ListKeyIDs()
}

// GenerateKey creates a new random AES-256 DEK, wraps it with the master key, and stores it.
func (k *KMSService) GenerateKey(keyID string) error {
	// 1) Generate a new DEK
	dek := make([]byte, 32) // AES-256
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	defer cryptoutil.Zeroize(dek)

	// 2) Wrap with masterKey
	wrapped, err := cryptoutil.WrapKey(k.masterKey, dek)
	if err != nil {
		return err
	}

	// 3) Store the wrapped key
	return k.store.StoreWrappedKey(keyID, wrapped)
}

// UnwrapKey returns the plaintext DEK for the given keyID.
func (k *KMSService) UnwrapKey(keyID string) ([]byte, error) {
	wrapped, err := k.store.LoadWrappedKey(keyID)
	if err != nil {
		return nil, err
	}
	dek, err := cryptoutil.UnwrapKey(k.masterKey, wrapped)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// EncryptData encrypts plaintext with the DEK identified by keyID using AES-GCM.
// It returns nonce || ciphertext.
func (k *KMSService) EncryptData(keyID string, plaintext []byte) ([]byte, error) {
	// 1) Retrieve and unwrap the DEK
	dek, err := k.UnwrapKey(keyID)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Zeroize(dek)

	// 2) Prepare AES-GCM
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3) Encrypt
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// 4) Return nonce || ciphertext
	return append(nonce, ciphertext...), nil
}

// DecryptData decrypts nonce||ciphertext using the DEK identified by keyID.
func (k *KMSService) DecryptData(keyID string, data []byte) ([]byte, error) {
	// 1) Unwrap
	dek, err := k.UnwrapKey(keyID)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Zeroize(dek)

	// 2) Prepare AES-GCM
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 3) Parse nonce and ciphertext
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// 4) Decrypt
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// TODO: RSA keypair generation, signing, and verification can be added similarly:
// - Generate an RSA private key, serialize (PKCS#8), wrap and store via store.StoreWrappedKey
// - Retrieve and unwrap for signing (crypto/rsa.SignPKCS1v15)
// - Verification can use the extracted public key plus crypto/rsa.VerifyPKCS1v15
