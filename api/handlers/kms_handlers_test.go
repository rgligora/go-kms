package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rgligora/go-kms/internal/kmspec"
	"github.com/rgligora/go-kms/internal/service"
	"github.com/rgligora/go-kms/internal/store"
)

// --- in-memory store -------------------------------------------------------

type memStore struct {
	mu   sync.RWMutex
	data map[string][]store.KeyVersion
	meta map[string]kmspec.KeySpec
}

func newMemStore() *memStore {
	return &memStore{
		data: make(map[string][]store.KeyVersion),
		meta: make(map[string]kmspec.KeySpec),
	}
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

// SecretStore

func (m *memStore) StoreWrappedKey(keyID string, version int, wrapped []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	wcopy := append([]byte(nil), wrapped...)
	m.data[keyID] = append(m.data[keyID], store.KeyVersion{
		Version:   version,
		Wrapped:   wcopy,
		CreatedAt: time.Now(),
	})
	return nil
}

func (m *memStore) LoadWrappedKey(keyID string) ([]store.KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kvs, ok := m.data[keyID]
	if !ok {
		return nil, store.ErrNotFound
	}
	out := make([]store.KeyVersion, len(kvs))
	for i, kv := range kvs {
		wcopy := append([]byte(nil), kv.Wrapped...)
		out[i] = store.KeyVersion{Version: kv.Version, Wrapped: wcopy, CreatedAt: kv.CreatedAt}
	}
	return out, nil
}

func (m *memStore) LoadLatestWrappedKey(keyID string) ([]byte, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kvs, ok := m.data[keyID]
	if !ok || len(kvs) == 0 {
		return nil, 0, store.ErrNotFound
	}
	latest := kvs[len(kvs)-1]
	return append([]byte(nil), latest.Wrapped...), latest.Version, nil
}

func (m *memStore) LoadWrappedKeyVersion(keyID string, version int) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, kv := range m.data[keyID] {
		if kv.Version == version {
			return append([]byte(nil), kv.Wrapped...), nil
		}
	}
	return nil, store.ErrNotFound
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

// --- test setup ------------------------------------------------------------

func setupHandler() http.Handler {
	ms := newMemStore()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	svc := service.NewKMSService(ms, masterKey)
	h := &Handler{Svc: svc}

	r := chi.NewRouter()

	// method not allowed
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})

	// key lifecycle
	r.Get("/v1/kms/keys", h.listKeys)
	r.Post("/v1/kms/keys", h.createKey)

	r.Route("/v1/kms/keys/{keyID}", func(r chi.Router) {
		// NB: use "/" not "" to avoid chi panic
		r.Get("/", h.getKey)
		r.Delete("/", h.deleteKey)
		r.Post("/rotate", h.rotateKey)
		r.Post("/recreate", h.recreateKey)
	})

	// data operations
	r.Post("/v1/kms/encrypt", h.encryptData)
	r.Post("/v1/kms/decrypt", h.decryptData)
	r.Post("/v1/kms/sign", h.signData)
	r.Post("/v1/kms/verify", h.verifyData)

	return r
}

// --- tests ------------------------------------------------------------

func TestKeyCRUD(t *testing.T) {
	h := setupHandler()

	// 1) list when empty
	t.Run("List empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/kms/keys", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var list []struct{} // empty array
		if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("want empty list, got %#v", list)
		}
	})

	// 2) create a key
	var keyID string
	t.Run("Create key success", func(t *testing.T) {
		body := `{"purpose":"encrypt","algorithm":"AES-256-GCM"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", w.Code)
		}
		var resp struct {
			KeyID     string              `json:"key_id"`
			Purpose   kmspec.KeyPurpose   `json:"purpose"`
			Algorithm kmspec.KeyAlgorithm `json:"algorithm"`
			Version   int                 `json:"version"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if resp.Purpose != "encrypt" || resp.Algorithm != "AES-256-GCM" || resp.Version != 1 || resp.KeyID == "" {
			t.Errorf("unexpected create response: %+v", resp)
		}
		keyID = resp.KeyID
	})

	// 3) create invalid JSON
	t.Run("Create invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(`{bad}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}
	})

	// 4) unsupported algorithm
	t.Run("Create unsupported algorithm", func(t *testing.T) {
		body := `{"purpose":"encrypt","algorithm":"UNKNOWN"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", w.Code)
		}
		var errResp map[string]string
		json.NewDecoder(w.Body).Decode(&errResp)
		if errResp["error"] == "" {
			t.Error("expected non-empty error message")
		}
	})

	// 5) list now has one
	t.Run("List one", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/kms/keys", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var list []struct {
			KeyID string `json:"key_id"`
		}
		if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if len(list) != 1 || list[0].KeyID != keyID {
			t.Errorf("expected one key %q, got %+v", keyID, list)
		}
	})

	// 6) get existing
	t.Run("Get existing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/kms/keys/"+keyID+"/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp struct {
			KeyID   string `json:"key_id"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if resp.KeyID != keyID || resp.Version != 1 {
			t.Errorf("unexpected get response: %+v", resp)
		}
	})

	// 7) get missing
	t.Run("Get missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/kms/keys/nosuch/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	// 8) method not allowed on list
	t.Run("Method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/v1/kms/keys", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d", w.Code)
		}
		var errResp map[string]string
		json.NewDecoder(w.Body).Decode(&errResp)
		if errResp["error"] != "method not allowed" {
			t.Errorf("expected 'method not allowed', got %q", errResp["error"])
		}
	})

	// 9) rotate existing
	t.Run("Rotate existing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys/"+keyID+"/rotate", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		var resp struct {
			Version int `json:"version"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if resp.Version != 2 {
			t.Errorf("expected version 2, got %d", resp.Version)
		}
	})

	// 10) rotate missing
	t.Run("Rotate missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys/nosuch/rotate", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	// 11) recreate existing → new keyID
	var newID string
	t.Run("Recreate existing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys/"+keyID+"/recreate", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", w.Code)
		}
		var resp struct {
			KeyID   string `json:"key_id"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode error: %v", err)
		}
		if resp.Version != 1 {
			t.Errorf("expected version 1, got %d", resp.Version)
		}
		if resp.KeyID == "" || resp.KeyID == keyID {
			t.Errorf("expected new key_id, got %q", resp.KeyID)
		}
		newID = resp.KeyID
	})

	// 12) recreate missing
	t.Run("Recreate missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys/nosuch/recreate", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})

	// 13) delete existing (the new one)
	t.Run("Delete existing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/kms/keys/"+newID+"/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", w.Code)
		}
	})

	// 14) delete missing
	t.Run("Delete missing", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/kms/keys/nosuch/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", w.Code)
		}
	})
}

func TestDataOperations(t *testing.T) {
	h := setupHandler()

	// create an encrypting key
	var keyEnc string
	{
		body := `{"purpose":"encrypt","algorithm":"AES-256-GCM"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var resp struct {
			KeyID string `json:"key_id"`
		}
		json.NewDecoder(w.Body).Decode(&resp)
		keyEnc = resp.KeyID
	}

	// create a signing key
	var keySign string
	{
		body := `{"purpose":"sign","algorithm":"RSA-4096"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		var resp struct {
			KeyID string `json:"key_id"`
		}
		json.NewDecoder(w.Body).Decode(&resp)
		keySign = resp.KeyID
	}

	msg := []byte("hello world")
	msgB64 := base64.StdEncoding.EncodeToString(msg)

	// ENCRYPT
	var ctB64 string
	t.Run("Encrypt success", func(t *testing.T) {
		body := `{"key_id":"` + keyEnc + `","plaintext":"` + msgB64 + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/encrypt", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("encrypt status %d", w.Code)
		}
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		ctB64 = resp["ciphertext"]
		if _, err := base64.StdEncoding.DecodeString(ctB64); err != nil {
			t.Errorf("ciphertext not base64: %v", err)
		}
	})

	t.Run("Encrypt invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/encrypt", bytes.NewBufferString(`{bad}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	t.Run("Encrypt invalid base64", func(t *testing.T) {
		body := `{"key_id":"` + keyEnc + `","plaintext":"!notb64!"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/encrypt", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	// DECRYPT
	t.Run("Decrypt success", func(t *testing.T) {
		body := `{"key_id":"` + keyEnc + `","ciphertext":"` + ctB64 + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/decrypt", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("decrypt status %d", w.Code)
		}
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["plaintext"] != msgB64 {
			t.Errorf("expected %q, got %q", msgB64, resp["plaintext"])
		}
	})

	t.Run("Decrypt invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/decrypt", bytes.NewBufferString(`{bad}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	t.Run("Decrypt invalid base64", func(t *testing.T) {
		body := `{"key_id":"` + keyEnc + `","ciphertext":"!!!"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/decrypt", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	// SIGN
	var sigB64 string
	t.Run("Sign success", func(t *testing.T) {
		body := `{"key_id":"` + keySign + `","message":"` + msgB64 + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/sign", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("sign status %d", w.Code)
		}
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		sigB64 = resp["signature"]
		if _, err := base64.StdEncoding.DecodeString(sigB64); err != nil {
			t.Errorf("signature not base64: %v", err)
		}
	})

	t.Run("Sign invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/sign", bytes.NewBufferString(`{bad}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	t.Run("Sign invalid base64", func(t *testing.T) {
		body := `{"key_id":"` + keySign + `","message":"!!!"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/sign", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("want 400, got %d", w.Code)
		}
	})

	// VERIFY
	t.Run("Verify good", func(t *testing.T) {
		body := `{"key_id":"` + keySign + `","message":"` + msgB64 + `","signature":"` + sigB64 + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/verify", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("verify status %d", w.Code)
		}
		var resp struct {
			Valid bool `json:"valid"`
		}
		json.NewDecoder(w.Body).Decode(&resp)
		if !resp.Valid {
			t.Error("expected valid=true")
		}
	})

	t.Run("Verify bad signature", func(t *testing.T) {
		bad := sigB64[:len(sigB64)-1] + "A"
		body := `{"key_id":"` + keySign + `","message":"` + msgB64 + `","signature":"` + bad + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/verify", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("verify status %d", w.Code)
		}
		var resp struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}
		json.NewDecoder(w.Body).Decode(&resp)
		if resp.Valid {
			t.Error("expected valid=false")
		}
		if resp.Error == "" {
			t.Error("expected an error message")
		}
	})
}
