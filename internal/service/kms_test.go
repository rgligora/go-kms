package service

import (
	"crypto/sha256"
	"testing"

	"github.com/rgligora/go-kms/internal/cryptoutil"
)

type memStore struct{ data map[string][]byte }

func newMemStore() *memStore                                  { return &memStore{data: map[string][]byte{}} }
func (m *memStore) StoreWrappedKey(id string, w []byte) error { m.data[id] = w; return nil }
func (m *memStore) LoadWrappedKey(id string) ([]byte, error)  { return m.data[id], nil }
func (m *memStore) DeleteWrappedKey(id string) error          { delete(m.data, id); return nil }
func (m *memStore) ListKeyIDs() ([]string, error)             { return nil, nil }
func (m *memStore) GetMasterKeySalt() ([]byte, error)         { return nil, nil }
func (m *memStore) SetMasterKeySalt([]byte) error             { return nil }

func TestEncryptDecryptCycle(t *testing.T) {
	pass, salt := []byte("p"), []byte("somesalt0000000")
	master := cryptoutil.DeriveMasterKey(pass, salt)
	svc := NewKMSService(newMemStore(), master)
	id := "test-key"
	if err := svc.GenerateKey(id); err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello world")
	ct, err := svc.EncryptData(id, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := svc.DecryptData(id, ct)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(pt) != sha256.Sum256(msg) {
		t.Fatal("decrypted plaintext != original")
	}
}
