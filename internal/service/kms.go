package service

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"strconv"

	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/kmspec"
	"github.com/rgligora/go-kms/internal/store"
)

var ErrKeyAlreadyExists = errors.New("key already exists")
var ErrKeyNotFound = store.ErrNotFound
var ErrUnsupportedAlgo = errors.New("unsupported signing algorithm")

// KMSService provides core key management operations.
type KMSService struct {
	store     store.SecretStore
	masterKey []byte
}

// NewKMSService constructs a new KMSService.
func NewKMSService(s store.SecretStore, masterKey []byte) *KMSService {
	return &KMSService{store: s, masterKey: masterKey}
}

func (k *KMSService) GetWrappedKey(spec kmspec.KeySpec) (keyAllVersions []store.KeyVersion, err error) {
	return k.store.LoadWrappedKey(spec)
}

func (k *KMSService) GetLatestWrappedKey(spec kmspec.KeySpec) (wrapped []byte, version int, err error) {
	return k.store.LoadLatestWrappedKey(spec)
}

func (k *KMSService) GetWrappedKeyVersion(spec kmspec.KeySpec, version int) (keySpecificVersion []byte, err error) {
	return k.store.LoadWrappedKeyVersion(spec, version)
}

func (k *KMSService) ListKeySpecs() ([]kmspec.KeySpec, error) {
	return k.store.ListKeySpecs()
}

// CreateKey creates a new random AES-256 DEK, wraps it with the master key, and stores it.
func (k *KMSService) CreateKey(spec kmspec.KeySpec) error {
	// 0) Bail if someone already created this key
	if _, _, err := k.store.LoadLatestWrappedKey(spec); err == nil {
		return ErrKeyAlreadyExists
	} else if !errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("checking existing key: %w", err)
	}
	var raw []byte
	switch spec.Algorithm {
	case kmspec.AlgAES256GCM:
		raw = make([]byte, 32)
		if n, err := rand.Read(raw); err != nil {
			return fmt.Errorf("generating AES-256 key: %w", err)
		} else if n != len(raw) {
			return fmt.Errorf("insufficient random bytes: got %d, want %d", n, len(raw))
		}

	case kmspec.AlgChaCha20Poly1305:
		raw = make([]byte, chacha20poly1305.KeySize)
		if n, err := rand.Read(raw); err != nil {
			return fmt.Errorf("generating ChaCha20 key: %w", err)
		} else if n != len(raw) {
			return fmt.Errorf("insufficient random bytes: got %d, want %d", n, len(raw))
		}

	case kmspec.AlgRSA4096:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("generating RSA-4096 key: %w", err)
		}
		raw, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("marshaling RSA private key: %w", err)
		}

	case kmspec.AlgECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generating ECDSA-P256 key: %w", err)
		}
		raw, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("marshaling ECDSA private key: %w", err)
		}

	default:
		return fmt.Errorf("unsupported algorithm %q", spec.Algorithm)
	}

	defer cryptoutil.Zeroize(raw)
	wrapped, err := cryptoutil.WrapKey(k.masterKey, raw)
	if err != nil {
		return fmt.Errorf("wrapping key: %w", err)
	}

	if err := k.store.StoreWrappedKey(spec, 1, wrapped); err != nil {
		return fmt.Errorf("storing wrapped key: %w", err)
	}
	return nil
}

// RotateKey bumps to version N+1
func (k *KMSService) RotateKey(spec kmspec.KeySpec) error {
	_, currentVer, err := k.store.LoadLatestWrappedKey(spec)
	if errors.Is(err, store.ErrNotFound) {
		return err
	}
	// generate a fresh raw just like in CreateKeyWithSpec
	specNew := spec
	// reuse CreateKeyWithSpec’s switch logic by calling it on a temp spec?
	// or duplicate the switch here; for brevity we'll duplicate:
	var raw []byte
	switch spec.Algorithm {
	case kmspec.AlgAES256GCM:
		raw = make([]byte, 32)
		if n, err := rand.Read(raw); err != nil || n != len(raw) {
			return fmt.Errorf("generating AES key: %w", err)
		}
	case kmspec.AlgChaCha20Poly1305:
		raw = make([]byte, chacha20poly1305.KeySize)
		if n, err := rand.Read(raw); err != nil || n != len(raw) {
			return fmt.Errorf("generating ChaCha20 key: %w", err)
		}
	case kmspec.AlgRSA4096:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return fmt.Errorf("generating RSA-4096 key: %w", err)
		}
		raw, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("marshaling RSA private key: %w", err)
		}
	case kmspec.AlgECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return fmt.Errorf("generating ECDSA-P256 key: %w", err)
		}
		raw, err = x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return fmt.Errorf("marshaling ECDSA private key: %w", err)
		}
	default:
		return fmt.Errorf("unsupported algorithm %q", spec.Algorithm)
	}

	defer cryptoutil.Zeroize(raw)
	wrapped, err := cryptoutil.WrapKey(k.masterKey, raw)
	if err != nil {
		return fmt.Errorf("wrapping rotated key: %w", err)
	}

	return k.store.StoreWrappedKey(specNew, currentVer+1, wrapped)
}

// DeleteKey removes *all* versions of the given spec.
func (k *KMSService) DeleteKey(spec kmspec.KeySpec) error {
	if err := k.store.DeleteWrappedKey(spec); err != nil {
		// propagate “not found” so callers can distinguish 404 vs 500
		return err
	}
	return nil
}

// RecreateKey wipes an existing key’s history and re-creates it at version 1.
// Returns ErrKeyNotFound if the keyID doesn’t already exist.
func (k *KMSService) RecreateKey(spec kmspec.KeySpec) error {
	// must already exist
	if _, _, err := k.store.LoadLatestWrappedKey(spec); err != nil {
		return err
	}
	if err := k.store.DeleteWrappedKey(spec); err != nil {
		return err
	}
	// reuse CreateKeyWithSpec logic but force version=1
	return k.CreateKey(spec)
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
func (k *KMSService) EncryptData(spec kmspec.KeySpec, pt []byte) ([]byte, error) {
	wrapped, ver, err := k.GetLatestWrappedKey(spec)
	if err != nil {
		return nil, err
	}
	raw, err := cryptoutil.UnwrapKey(k.masterKey, wrapped)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Zeroize(raw)

	prefix := []byte(fmt.Sprintf("v%d:", ver))

	switch spec.Algorithm {
	case kmspec.AlgAES256GCM:
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ct := gcm.Seal(nil, nonce, pt, prefix)
		return append(append(prefix, nonce...), ct...), nil

	case kmspec.AlgChaCha20Poly1305:
		aead, err := chacha20poly1305.New(raw)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, chacha20poly1305.NonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		ct := aead.Seal(nil, nonce, pt, prefix)
		return append(append(prefix, nonce...), ct...), nil

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm %q", spec.Algorithm)
	}
}

// DecryptData decrypts data in the form:
//
//	versionPrefix || nonce || ciphertext
//
// where versionPrefix is "v<version>:".
func (k *KMSService) DecryptDataWithSpec(spec kmspec.KeySpec, data []byte) ([]byte, error) {
	// split off version prefix "vN:"
	idx := bytes.IndexByte(data, ':')
	if idx < 0 {
		return nil, fmt.Errorf("invalid payload: missing version prefix")
	}
	verStr := string(data[1:idx])
	ver, err := strconv.Atoi(verStr)
	if err != nil {
		return nil, fmt.Errorf("invalid version %q: %w", verStr, err)
	}
	wrapped, err := k.GetWrappedKeyVersion(spec, ver)
	if err != nil {
		return nil, err
	}
	raw, err := cryptoutil.UnwrapKey(k.masterKey, wrapped)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Zeroize(raw)

	prefix := data[:idx+1]
	rest := data[idx+1:]

	switch spec.Algorithm {
	case kmspec.AlgAES256GCM:
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(rest) < gcm.NonceSize() {
			return nil, errors.New("ciphertext too short")
		}
		nonce, ct := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
		return gcm.Open(nil, nonce, ct, prefix)

	case kmspec.AlgChaCha20Poly1305:
		aead, err := chacha20poly1305.New(raw)
		if err != nil {
			return nil, err
		}
		if len(rest) < chacha20poly1305.NonceSize {
			return nil, errors.New("ciphertext too short")
		}
		nonce, ct := rest[:chacha20poly1305.NonceSize], rest[chacha20poly1305.NonceSize:]
		return aead.Open(nil, nonce, ct, prefix)

	default:
		return nil, fmt.Errorf("unsupported decryption algorithm %q", spec.Algorithm)
	}
}

// SignData fetches & unwraps the latest private key for keySpec, then returns
// a signature over SHA-256(message).
func (k *KMSService) SignData(spec kmspec.KeySpec, message []byte) ([]byte, error) {
	// 1) Load the wrapped key
	wrapped, _, err := k.store.LoadLatestWrappedKey(spec)
	if err != nil {
		return nil, err
	}

	// 2) Unwrap under the master key
	privDER, err := cryptoutil.UnwrapKey(k.masterKey, wrapped)
	if err != nil {
		return nil, err
	}
	defer cryptoutil.Zeroize(privDER)

	// 3) Parse the PKCS#8 DER
	keyIfc, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	// 4) Dispatch based on actual key type
	switch priv := keyIfc.(type) {
	case *rsa.PrivateKey:
		// RSA-PKCS1v1.5 over SHA-256
		h := sha256.Sum256(message)
		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])

	case *ecdsa.PrivateKey:
		// ECDSA (ASN.1 DER) over SHA-256
		h := sha256.Sum256(message)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
		if err != nil {
			return nil, fmt.Errorf("ecdsa signing: %w", err)
		}
		return sig, nil

	default:
		return nil, ErrUnsupportedAlgo
	}
}

// VerifySignature loads & unwraps the signing private key, derives its public half,
// and then verifies that sig is a valid signature over message.
func (k *KMSService) VerifySignature(spec kmspec.KeySpec, message, sig []byte) error {
	// 1) Load wrapped
	wrapped, _, err := k.store.LoadLatestWrappedKey(spec)
	if err != nil {
		return err
	}

	// 2) Unwrap
	privDER, err := cryptoutil.UnwrapKey(k.masterKey, wrapped)
	if err != nil {
		return err
	}
	defer cryptoutil.Zeroize(privDER)

	// 3) Parse
	keyIfc, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return fmt.Errorf("parsing private key: %w", err)
	}

	// 4) Dispatch by type
	switch priv := keyIfc.(type) {
	case *rsa.PrivateKey:
		pub := &priv.PublicKey
		h := sha256.Sum256(message)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)

	case *ecdsa.PrivateKey:
		pub := &priv.PublicKey
		h := sha256.Sum256(message)
		if ok := ecdsa.VerifyASN1(pub, h[:], sig); !ok {
			return errors.New("ecdsa signature verification failed")
		}
		return nil

	default:
		return ErrUnsupportedAlgo
	}
}
