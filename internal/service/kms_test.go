package service

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/store"
)

// memStore implements store.SecretStore in-memory for testing.
type memStore struct {
	data map[string][][]byte // data[keyID][version-1] = wrapped DEK
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string][][]byte)}
}

func (m *memStore) StoreWrappedKey(keyID string, version int, wrapped []byte) error {
	versions := m.data[keyID]
	if len(versions) < version {
		newVers := make([][]byte, version)
		copy(newVers, versions)
		versions = newVers
	}
	versions[version-1] = append([]byte(nil), wrapped...)
	m.data[keyID] = versions
	return nil
}

func (m *memStore) LoadLatestWrappedKey(keyID string) ([]byte, int, error) {
	versions, ok := m.data[keyID]
	if !ok || len(versions) == 0 || versions[len(versions)-1] == nil {
		return nil, 0, store.ErrNotFound
	}
	latest := versions[len(versions)-1]
	return append([]byte(nil), latest...), len(versions), nil
}

func (m *memStore) LoadWrappedKeyVersion(keyID string, version int) ([]byte, error) {
	versions, ok := m.data[keyID]
	if !ok || version < 1 || version > len(versions) || versions[version-1] == nil {
		return nil, store.ErrNotFound
	}
	return append([]byte(nil), versions[version-1]...), nil
}

// The following methods satisfy the interface but aren’t used in this test:
func (m *memStore) LoadWrappedKey(keyID string) ([]store.KeyVersion, error) {
	versions, ok := m.data[keyID]
	if !ok {
		return nil, store.ErrNotFound
	}
	var out []store.KeyVersion
	for i, wrapped := range versions {
		if wrapped == nil {
			continue
		}
		out = append(out, store.KeyVersion{
			Version:   i + 1,
			Wrapped:   append([]byte(nil), wrapped...),
			CreatedAt: time.Now(),
		})
	}
	return out, nil
}

func (m *memStore) DeleteWrappedKey(keyID string) error {
	if _, ok := m.data[keyID]; !ok {
		return store.ErrNotFound
	}
	delete(m.data, keyID)
	return nil
}

func (m *memStore) ListKeyIDs() ([]string, error) {
	var ids []string
	for k := range m.data {
		ids = append(ids, k)
	}
	return ids, nil
}

func TestEncryptDecryptCycle(t *testing.T) {
	passphrase := []byte("p")
	salt := []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(passphrase, salt)

	svc := NewKMSService(newMemStore(), master)
	const keyID = "test-key"

	// Create the key
	if err := svc.CreateKey(keyID); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	msg := []byte("hello world")

	// Encrypt
	ct, err := svc.EncryptData(keyID, msg)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	// Decrypt
	pt, err := svc.DecryptData(keyID, ct)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	// Verify
	if sha256.Sum256(pt) != sha256.Sum256(msg) {
		t.Fatal("decrypted plaintext != original")
	}
}

func TestGenerateRSAKey_SignVerify(t *testing.T) {
	passphrase := []byte("p")
	salt := []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(passphrase, salt)
	svc := NewKMSService(newMemStore(), master)
	const keyID = "rsa-key"

	// 1) Generate a new RSA key
	if err := svc.GenerateRSAKey(keyID, 2048); err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	// 2) Generating again should return ErrKeyAlreadyExists
	if err := svc.GenerateRSAKey(keyID, 2048); !errors.Is(err, ErrKeyAlreadyExists) {
		t.Fatalf("expected ErrKeyAlreadyExists, got %v", err)
	}

	// 3) Sign and verify a message
	msg := []byte("hello RSA!")
	sig, err := svc.SignData(keyID, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	if err := svc.VerifySignature(keyID, msg, sig); err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
}

func TestVerifySignature_Failure(t *testing.T) {
	passphrase := []byte("p")
	salt := []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(passphrase, salt)
	svc := NewKMSService(newMemStore(), master)
	const keyID = "rsa-key2"

	if err := svc.GenerateRSAKey(keyID, 2048); err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	msg := []byte("test message")
	sig, err := svc.SignData(keyID, msg)
	if err != nil {
		t.Fatalf("SignData: %v", err)
	}

	// a) Tampered message
	if err := svc.VerifySignature(keyID, []byte("tampered"), sig); err == nil {
		t.Fatal("expected VerifySignature to fail for tampered message")
	}

	// b) Tampered signature
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0xFF
	if err := svc.VerifySignature(keyID, msg, badSig); err == nil {
		t.Fatal("expected VerifySignature to fail for tampered signature")
	}
}
