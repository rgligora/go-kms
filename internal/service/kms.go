package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/store"
)

var ErrKeyAlreadyExists = errors.New("key already exists")
var ErrKeyNotFound = store.ErrNotFound

// KMSService provides core key management operations.
type KMSService struct {
	store     store.SecretStore
	masterKey []byte
}

// NewKMSService constructs a new KMSService.
func NewKMSService(s store.SecretStore, masterKey []byte) *KMSService {
	return &KMSService{store: s, masterKey: masterKey}
}

func (k *KMSService) GetWrappedKey(keyID string) (keyAllVersions []store.KeyVersion, err error) {
	return k.store.LoadWrappedKey(keyID)
}

func (k *KMSService) GetLatestWrappedKey(keyID string) (wrapped []byte, version int, err error) {
	return k.store.LoadLatestWrappedKey(keyID)
}

func (k *KMSService) GetWrappedKeyVersion(keyID string, version int) (keySpecificVersion []byte, err error) {
	return k.store.LoadWrappedKeyVersion(keyID, version)
}

func (k *KMSService) ListKeyIds() ([]string, error) {
	return k.store.ListKeyIDs()
}

// CreateKey creates a new random AES-256 DEK, wraps it with the master key, and stores it.
func (k *KMSService) CreateKey(keyID string) error {
	// 0) Bail if someone already created this key
	if _, _, err := k.store.LoadLatestWrappedKey(keyID); err == nil {
		return ErrKeyAlreadyExists
	} else if !errors.Is(err, ErrKeyNotFound) {
		return err
	}

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
	return k.store.StoreWrappedKey(keyID, 1, wrapped)
}

// RotateKey bumps to version N+1
func (k *KMSService) RotateKey(keyID string) error {
	_, currentVer, err := k.store.LoadLatestWrappedKey(keyID)
	if errors.Is(err, store.ErrNotFound) {
		return err
	}

	newDek := make([]byte, 32) // AES-256
	if _, err := rand.Read(newDek); err != nil {
		return err
	}
	defer cryptoutil.Zeroize(newDek)

	wrapped, err := cryptoutil.WrapKey(k.masterKey, newDek)
	if err != nil {
		return err
	}
	return k.store.StoreWrappedKey(keyID, currentVer+1, wrapped)
}

// DeleteKey removes *all* versions of the given keyID.
func (k *KMSService) DeleteKey(keyID string) error {
	if err := k.store.DeleteWrappedKey(keyID); err != nil {
		// propagate “not found” so callers can distinguish 404 vs 500
		return err
	}
	return nil
}

// RecreateKey wipes an existing key’s history and re-creates it at version 1.
// Returns ErrKeyNotFound if the keyID doesn’t already exist.
func (k *KMSService) RecreateKey(keyID string) error {
	// 0) Ensure the key already exists
	if _, _, err := k.store.LoadLatestWrappedKey(keyID); err != nil {
		// forward NotFound as ErrKeyNotFound
		if errors.Is(err, store.ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}

	// 1) Delete all versions
	if err := k.store.DeleteWrappedKey(keyID); err != nil {
		return err
	}

	// 2) Generate a new DEK
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	defer cryptoutil.Zeroize(dek)

	// 3) Wrap and store as version 1
	wrapped, err := cryptoutil.WrapKey(k.masterKey, dek)
	if err != nil {
		return err
	}
	return k.store.StoreWrappedKey(keyID, 1, wrapped)
}

// UnwrapKey returns the plaintext DEK for the given keyID.
func (k *KMSService) UnwrapKey(wrappedKey []byte) ([]byte, error) {
	dek, err := cryptoutil.UnwrapKey(k.masterKey, wrappedKey)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// EncryptData encrypts plaintext with the latest DEK identified by keyID using AES-GCM
// It returns:   versionPrefix || nonce || ciphertext
// where versionPrefix is "v<version>:".
func (k *KMSService) EncryptData(keyID string, plaintext []byte) ([]byte, error) {
	// 1) Retrieve and unwrap the DEK
	wrappedKey, version, err := k.GetLatestWrappedKey(keyID)
	if err != nil {
		return nil, err
	}
	dek, err := k.UnwrapKey(wrappedKey)
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

	// 3) Build the version prefix and nonce
	versionPrefix := []byte(fmt.Sprintf("v%d:", version))
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 4) Seal plaintext, authenticating the versionPrefix as AAD
	//    output = nonce || ciphertext-with-tag
	ciphertext := gcm.Seal(nil, nonce, plaintext, versionPrefix)

	// 5) Concatenate: versionPrefix || nonce || ciphertext
	out := make([]byte, 0, len(versionPrefix)+len(nonce)+len(ciphertext))
	out = append(out, versionPrefix...) // v1:
	out = append(out, nonce...)         // 12-byte random nonce
	out = append(out, ciphertext...)    // actual ciphertext + GCM tag

	return out, nil
}

// DecryptData decrypts data in the form:
//
//	versionPrefix || nonce || ciphertext
//
// where versionPrefix is "v<version>:".
func (k *KMSService) DecryptData(keyID string, data []byte) ([]byte, error) {
	// 1) Pull off the versionPrefix ("vN:")
	idx := bytes.IndexByte(data, ':')
	if idx < 0 {
		return nil, fmt.Errorf("invalid payload: missing version prefix")
	}
	versionPrefix := data[:idx+1]     // e.g. []byte("v1:")
	versionStr := string(data[1:idx]) // e.g. "1"
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: %w", versionStr, err)
	}
	// 2) Retrieve and unwrap the DEK
	wrappedKey, err := k.GetWrappedKeyVersion(keyID, version)
	if err != nil {
		return nil, err
	}
	dek, err := k.UnwrapKey(wrappedKey)
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

	// 4) Slice out nonce and ciphertext
	rest := data[idx+1:]
	nonceSize := gcm.NonceSize()
	if len(rest) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := rest[:nonceSize], rest[nonceSize:]

	// 5) Decrypt, authenticating the versionPrefix as AAD
	//    If the versionPrefix was tampered with, this will error.
	return gcm.Open(nil, nonce, ciphertext, versionPrefix)
}

// TODO: RSA keypair generation, signing, and verification can be added similarly:
// - Generate an RSA private key, serialize (PKCS#8), wrap and store via store.StoreWrappedKey
// - Retrieve and unwrap for signing (crypto/rsa.SignPKCS1v15)
// - Verification can use the extracted public key plus crypto/rsa.VerifyPKCS1v15
