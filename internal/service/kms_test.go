// internal/service/kms_test.go
package service

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/kmspec"
	"github.com/rgligora/go-kms/internal/store"
)

// memStore implements store.SecretStore in-memory for testing.
type memStore struct {
	data map[string][][]byte // data[specKey][version-1] = wrapped
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string][][]byte)}
}

func specKey(spec kmspec.KeySpec) string {
	return spec.KeyID + "|" + string(spec.Purpose) + "|" + string(spec.Algorithm)
}

func (m *memStore) StoreWrappedKey(spec kmspec.KeySpec, version int, wrapped []byte) error {
	key := specKey(spec)
	vers := m.data[key]
	if len(vers) < version {
		newVers := make([][]byte, version)
		copy(newVers, vers)
		vers = newVers
	}
	vers[version-1] = append([]byte(nil), wrapped...)
	m.data[key] = vers
	return nil
}

func (m *memStore) LoadWrappedKey(spec kmspec.KeySpec) ([]store.KeyVersion, error) {
	key := specKey(spec)
	vers, ok := m.data[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	var out []store.KeyVersion
	for i, w := range vers {
		if w == nil {
			continue
		}
		out = append(out, store.KeyVersion{
			Version:   i + 1,
			Wrapped:   append([]byte(nil), w...),
			CreatedAt: time.Now(),
		})
	}
	if len(out) == 0 {
		return nil, store.ErrNotFound
	}
	return out, nil
}

func (m *memStore) LoadLatestWrappedKey(spec kmspec.KeySpec) ([]byte, int, error) {
	key := specKey(spec)
	vers, ok := m.data[key]
	if !ok || len(vers) == 0 || vers[len(vers)-1] == nil {
		return nil, 0, store.ErrNotFound
	}
	latest := vers[len(vers)-1]
	return append([]byte(nil), latest...), len(vers), nil
}

func (m *memStore) LoadWrappedKeyVersion(spec kmspec.KeySpec, version int) ([]byte, error) {
	key := specKey(spec)
	vers, ok := m.data[key]
	if !ok || version < 1 || version > len(vers) || vers[version-1] == nil {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), vers[version-1]...), nil
}

func (m *memStore) DeleteWrappedKey(spec kmspec.KeySpec) error {
	key := specKey(spec)
	if _, ok := m.data[key]; !ok {
		return store.ErrNotFound
	}
	delete(m.data, key)
	return nil
}

func (m *memStore) ListKeySpecs() ([]kmspec.KeySpec, error) {
	var specs []kmspec.KeySpec
	for key := range m.data {
		parts := strings.SplitN(key, "|", 3)
		specs = append(specs, kmspec.KeySpec{
			KeyID:     parts[0],
			Purpose:   kmspec.KeyPurpose(parts[1]),
			Algorithm: kmspec.KeyAlgorithm(parts[2]),
		})
	}
	return specs, nil
}

// ---------------------------------------------------------------------------

func TestEncryptDecryptCycle(t *testing.T) {
	passphrase := []byte("p")
	salt := []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(passphrase, salt)

	svc := NewKMSService(newMemStore(), master)
	spec := kmspec.KeySpec{
		KeyID:     "test-key",
		Purpose:   kmspec.PurposeEncrypt,
		Algorithm: kmspec.AlgAES256GCM,
	}

	// 1) Create the AES key
	if err := svc.CreateKey(spec); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	msg := []byte("hello world")

	// 2) Encrypt
	ct, err := svc.EncryptData(spec, msg)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// 3) Decrypt
	pt, err := svc.DecryptDataWithSpec(spec, ct)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	// 4) Verify round-trip
	if sha256.Sum256(pt) != sha256.Sum256(msg) {
		t.Fatal("decrypted plaintext != original")
	}
}

func TestGenerateAndSignVerifyRSA(t *testing.T) {
	passphrase := []byte("p")
	salt := []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(passphrase, salt)
	svc := NewKMSService(newMemStore(), master)

	spec := kmspec.KeySpec{
		KeyID:     "rsa-key",
		Purpose:   kmspec.PurposeSign,
		Algorithm: kmspec.AlgRSA4096,
	}

	// 1) Create RSA signing key
	if err := svc.CreateKey(spec); err != nil {
		t.Fatalf("CreateKey(RSA): %v", err)
	}

	// 2) Creating again should error
	if err := svc.CreateKey(spec); !errors.Is(err, ErrKeyAlreadyExists) {
		t.Fatalf("expected ErrKeyAlreadyExists, got %v", err)
	}

	// 3) Sign & verify a message
	msg := []byte("hello RSA!")
	sig, err := svc.SignData(spec, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	if err := svc.VerifySignature(spec, msg, sig); err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
}

func TestVerifySignatureFailure(t *testing.T) {
	passphrase := []byte("p")
	salt := []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(passphrase, salt)
	svc := NewKMSService(newMemStore(), master)

	spec := kmspec.KeySpec{
		KeyID:     "rsa-key2",
		Purpose:   kmspec.PurposeSign,
		Algorithm: kmspec.AlgRSA4096,
	}

	if err := svc.CreateKey(spec); err != nil {
		t.Fatalf("CreateKey(RSA): %v", err)
	}

	msg := []byte("test message")
	sig, err := svc.SignData(spec, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	// a) Tampered message
	if err := svc.VerifySignature(spec, []byte("tampered"), sig); err == nil {
		t.Fatal("expected VerifySignature to fail for tampered message")
	}

	// b) Tampered signature
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xFF
	if err := svc.VerifySignature(spec, msg, badSig); err == nil {
		t.Fatal("expected VerifySignature to fail for tampered signature")
	}
}
