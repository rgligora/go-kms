package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rgligora/go-kms/internal/service"
)

// memStore is a simple in-memory implementation of store.SecretStore
type memStore struct {
	mu    sync.RWMutex
	store map[string][]byte
}

func newMemStore() *memStore {
	return &memStore{store: make(map[string][]byte)}
}

func (m *memStore) StoreWrappedKey(id string, wrapped []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[id] = append([]byte(nil), wrapped...) // copy to avoid mutation
	return nil
}

func (m *memStore) LoadWrappedKey(id string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	wrapped, ok := m.store[id]
	if !ok {
		return nil, nil // You may need to define this in your service package
	}
	return append([]byte(nil), wrapped...), nil
}

func (m *memStore) DeleteWrappedKey(keyID string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	delete(m.store, keyID)
	return nil
}

func (m *memStore) ListKeyIDs() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.store))
	for k := range m.store {
		ids = append(ids, k)
	}
	return ids, nil
}

func setupHandler() *Handler {
	masterKey := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	svc := service.NewKMSService(newMemStore(), masterKey)
	return NewHandler(svc)
}

func TestHandleKeys(t *testing.T) {
	h := setupHandler()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := bytes.NewBufferString(`{"key_id":"foo"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", body)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if resp["key_id"] != "foo" {
		t.Fatalf("unexpected response: %v", resp)
	}
}
