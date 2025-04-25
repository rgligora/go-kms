package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgligora/go-kms/internal/service"
	"github.com/rgligora/go-kms/internal/store"
)

// --- in-memory SecretStore ------------------------------------------------

type memStore struct {
	mu   sync.RWMutex
	data map[string][]store.KeyVersion
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string][]store.KeyVersion)}
}

func (m *memStore) StoreWrappedKey(keyID string, version int, wrapped []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	wcopy := append([]byte(nil), wrapped...)
	kv := store.KeyVersion{Version: version, Wrapped: wcopy, CreatedAt: time.Now()}
	m.data[keyID] = append(m.data[keyID], kv)
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
	return nil
}

func (m *memStore) ListKeyIDs() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.data))
	for id := range m.data {
		ids = append(ids, id)
	}
	return ids, nil
}

// --- test setup ------------------------------------------------------------

func setupHandler() *Handler {
	ms := newMemStore()
	masterKey := []byte("0123456789abcdef0123456789abcdef") // 32-byte
	svc := service.NewKMSService(ms, masterKey)
	return NewHandler(svc)
}

// --- tests for POST /v1/kms/keys -------------------------------------------

func TestHandleKeys(t *testing.T) {
	h := setupHandler()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	cases := []struct {
		name       string
		method     string
		url        string
		body       string
		wantStatus int
		wantResp   map[string]string
	}{
		{
			name:       "Create key success",
			method:     http.MethodPost,
			url:        "/v1/kms/keys",
			body:       `{"key_id":"foo"}`,
			wantStatus: http.StatusCreated,
			wantResp:   map[string]string{"key_id": "foo"},
		},
		{
			name:       "Invalid method",
			method:     http.MethodGet,
			url:        "/v1/kms/keys",
			body:       ``,
			wantStatus: http.StatusMethodNotAllowed,
			wantResp:   map[string]string{"error": "method not allowed"},
		},
		{
			name:       "Missing key_id",
			method:     http.MethodPost,
			url:        "/v1/kms/keys",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
			wantResp:   map[string]string{"error": "key_id is required"},
		},
		{
			name:       "Invalid JSON",
			method:     http.MethodPost,
			url:        "/v1/kms/keys",
			body:       `{invalid json}`,
			wantStatus: http.StatusBadRequest,
			wantResp:   map[string]string{"error": "invalid JSON"},
		},
	}

	for _, tc := range cases {
		tc := tc // capture
		t.Run(tc.name, func(t *testing.T) {
			var buf *bytes.Buffer
			if tc.body != "" {
				buf = bytes.NewBufferString(tc.body)
			} else {
				buf = &bytes.Buffer{}
			}
			req := httptest.NewRequest(tc.method, tc.url, buf)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("%s: expected status %d, got %d", tc.name, tc.wantStatus, w.Code)
			}
			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("%s: decode error: %v", tc.name, err)
			}
			for k, v := range tc.wantResp {
				if got, ok := resp[k]; !ok || got != v {
					t.Errorf("%s: want resp[%q]=%q, got %q", tc.name, k, v, got)
				}
			}
		})
	}
}

// --- tests for GET/DELETE/POST(rotate)/POST(recreate) /v1/kms/keys/{keyID} -------------

func TestHandleKeyByID(t *testing.T) {
	h := setupHandler()
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// pre-create "foo"
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(`{"key_id":"foo"}`))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("setup: create foo expected 201, got %d", w.Code)
		}
	}

	cases := []struct {
		name         string
		method, url  string
		wantStatus   int
		wantContains string // substring that must appear in the body
	}{
		{
			name:         "Get existing key",
			method:       http.MethodGet,
			url:          "/v1/kms/keys/foo",
			wantStatus:   http.StatusOK,
			wantContains: `"wrapped_keys"`,
		},
		{
			name:         "Get missing key",
			method:       http.MethodGet,
			url:          "/v1/kms/keys/bar",
			wantStatus:   http.StatusNotFound,
			wantContains: `"error"`,
		},
		{
			name:       "Rotate existing key",
			method:     http.MethodPost,
			url:        "/v1/kms/keys/foo/rotate",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Rotate missing key",
			method:     http.MethodPost,
			url:        "/v1/kms/keys/baz/rotate",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "Recreate existing key",
			method:     http.MethodPost,
			url:        "/v1/kms/keys/foo/recreate",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "Recreate missing key",
			method:     http.MethodPost,
			url:        "/v1/kms/keys/baz/recreate",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "Delete existing key",
			method:     http.MethodDelete,
			url:        "/v1/kms/keys/foo",
			wantStatus: http.StatusNoContent,
		},
		{
			name:         "Delete missing key",
			method:       http.MethodDelete,
			url:          "/v1/kms/keys/bar",
			wantStatus:   http.StatusNotFound,
			wantContains: `"error"`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("%s: expected status %d, got %d", tc.name, tc.wantStatus, w.Code)
			}
			if tc.wantContains != "" {
				if !strings.Contains(w.Body.String(), tc.wantContains) {
					t.Errorf("%s: expected body to contain %q, got %q",
						tc.name, tc.wantContains, w.Body.String())
				}
			}
		})
	}
}
