// internal/service/kms_test.go
package service

import (
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/kmspec"
	"github.com/rgligora/go-kms/internal/store"
)

// memStore implements both SecretStore and KeyMetadataStore in memory.
type memStore struct {
	mu   sync.RWMutex
	data map[string][][]byte
	meta map[string]kmspec.KeySpec
}

func newMemStore() *memStore {
	return &memStore{
		data: make(map[string][][]byte),
		meta: make(map[string]kmspec.KeySpec),
	}
}

// SecretStore

func (m *memStore) StoreWrappedKey(keyID string, version int, wrapped []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	vers := m.data[keyID]
	if len(vers) < version {
		newVers := make([][]byte, version)
		copy(newVers, vers)
		vers = newVers
	}
	vers[version-1] = append([]byte(nil), wrapped...)
	m.data[keyID] = vers
	return nil
}

func (m *memStore) LoadWrappedKey(keyID string) ([]store.KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vers, ok := m.data[keyID]
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

func (m *memStore) LoadLatestWrappedKey(keyID string) ([]byte, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vers, ok := m.data[keyID]
	if !ok || len(vers) == 0 || vers[len(vers)-1] == nil {
		return nil, 0, store.ErrNotFound
	}
	latest := vers[len(vers)-1]
	return append([]byte(nil), latest...), len(vers), nil
}

func (m *memStore) LoadWrappedKeyVersion(keyID string, version int) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	vers, ok := m.data[keyID]
	if !ok || version < 1 || version > len(vers) || vers[version-1] == nil {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), vers[version-1]...), nil
}

func (m *memStore) DeleteWrappedKey(keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[keyID]; !ok {
		return store.ErrNotFound
	}
	delete(m.data, keyID)
	delete(m.meta, keyID)
	return nil
}

// KeyMetadataStore

func (m *memStore) StoreKeyMetadata(spec kmspec.KeySpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.meta[spec.KeyID] = spec
	return nil
}

func (m *memStore) GetKeyMetadata(keyID string) (kmspec.KeySpec, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	spec, ok := m.meta[keyID]
	if !ok {
		return kmspec.KeySpec{}, store.ErrNotFound
	}
	return spec, nil
}

func (m *memStore) ListKeySpecs() ([]kmspec.KeySpec, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]kmspec.KeySpec, 0, len(m.meta))
	for _, spec := range m.meta {
		out = append(out, spec)
	}
	return out, nil
}

// ---------------------------------------------------------------------------

func deriveService(t *testing.T) *KMSService {
	t.Helper()
	pass := []byte("test-pass")
	salt := []byte("fixed-salt-123456")
	master := cryptoutil.DeriveMasterKey(pass, salt)
	cryptoutil.Zeroize(pass)
	return NewKMSService(newMemStore(), master)
}

func TestKeyLifecycle(t *testing.T) {
	svc := deriveService(t)

	// Create
	ki, err := svc.CreateKey(kmspec.PurposeEncrypt, kmspec.AlgAES256GCM)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if ki.Version != 1 {
		t.Errorf("got version %d; want 1", ki.Version)
	}

	// List
	all, err := svc.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(all) != 1 || all[0].KeyID != ki.KeyID {
		t.Errorf("ListKeys = %+v; want one entry with KeyID %q", all, ki.KeyID)
	}

	// Get
	got, err := svc.GetKey(ki.KeyID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("GetKey.Version = %d; want 1", got.Version)
	}

	// Rotate
	rot, err := svc.RotateKey(ki.KeyID)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if rot.Version != 2 {
		t.Errorf("RotateKey.Version = %d; want 2", rot.Version)
	}

	// Delete
	if err := svc.DeleteKey(ki.KeyID); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := svc.GetKey(ki.KeyID); err == nil {
		t.Errorf("GetKey after delete: expected error, got nil")
	}

	// Recreate missing
	if _, err := svc.RecreateKey(ki.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RecreateKey missing: got %v; want ErrNotFound", err)
	}
}

func TestEncryptDecryptAES(t *testing.T) {
	svc := deriveService(t)

	ki, err := svc.CreateKey(kmspec.PurposeEncrypt, kmspec.AlgAES256GCM)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	plain := []byte("hello aes")
	ct, err := svc.EncryptData(ki.KeyID, plain)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	pt, err := svc.DecryptData(ki.KeyID, ct)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if sha256.Sum256(pt) != sha256.Sum256(plain) {
		t.Errorf("decrypted != original")
	}
}

func TestEncryptDecryptChaCha(t *testing.T) {
	svc := deriveService(t)

	ki, err := svc.CreateKey(kmspec.PurposeEncrypt, kmspec.AlgChaCha20Poly1305)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	plain := []byte("hello chacha")
	ct, err := svc.EncryptData(ki.KeyID, plain)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	pt, err := svc.DecryptData(ki.KeyID, ct)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if sha256.Sum256(pt) != sha256.Sum256(plain) {
		t.Errorf("decrypted != original")
	}
}

func TestSignVerifyRSA(t *testing.T) {
	svc := deriveService(t)

	ki, err := svc.CreateKey(kmspec.PurposeSign, kmspec.AlgRSA4096)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	msg := []byte("hello rsa")
	sig, err := svc.SignData(ki.KeyID, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if err := svc.VerifySignature(ki.KeyID, msg, sig); err != nil {
		t.Errorf("VerifySignature: %v", err)
	}
}

func TestSignVerifyECDSA(t *testing.T) {
	svc := deriveService(t)

	ki, err := svc.CreateKey(kmspec.PurposeSign, kmspec.AlgECDSAP256)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	msg := []byte("hello ecdsa")
	sig, err := svc.SignData(ki.KeyID, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}
	if err := svc.VerifySignature(ki.KeyID, msg, sig); err != nil {
		t.Errorf("VerifySignature: %v", err)
	}
}

func TestVerifySignatureFailure(t *testing.T) {
	svc := deriveService(t)

	ki, err := svc.CreateKey(kmspec.PurposeSign, kmspec.AlgRSA4096)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	msg := []byte("message")
	sig, _ := svc.SignData(ki.KeyID, msg)

	// wrong message
	if err := svc.VerifySignature(ki.KeyID, []byte("bad"), sig); err == nil {
		t.Errorf("expected failure for bad message")
	}
	// tampered sig
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xFF
	if err := svc.VerifySignature(ki.KeyID, msg, bad); err == nil {
		t.Errorf("expected failure for bad signature")
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	svc := deriveService(t)

	_, err := svc.CreateKey(kmspec.PurposeEncrypt, kmspec.KeyAlgorithm("BAD-ALG"))
	if err == nil || !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("expected unsupported algorithm error, got %v", err)
	}
}
