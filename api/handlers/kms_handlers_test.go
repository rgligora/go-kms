// internal/api/kms_handler_test.go
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

	"github.com/rgligora/go-kms/internal/kmspec"
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

func specKey(spec kmspec.KeySpec) string {
	return spec.KeyID + "|" + string(spec.Purpose) + "|" + string(spec.Algorithm)
}

func (m *memStore) StoreWrappedKey(spec kmspec.KeySpec, version int, wrapped []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := specKey(spec)
	wcopy := append([]byte(nil), wrapped...)
	kv := store.KeyVersion{Version: version, Wrapped: wcopy, CreatedAt: time.Now()}
	m.data[key] = append(m.data[key], kv)
	return nil
}

func (m *memStore) LoadWrappedKey(spec kmspec.KeySpec) ([]store.KeyVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kvs, ok := m.data[specKey(spec)]
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

func (m *memStore) LoadLatestWrappedKey(spec kmspec.KeySpec) ([]byte, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	kvs, ok := m.data[specKey(spec)]
	if !ok || len(kvs) == 0 {
		return nil, 0, store.ErrNotFound
	}
	latest := kvs[len(kvs)-1]
	return append([]byte(nil), latest.Wrapped...), latest.Version, nil
}

func (m *memStore) LoadWrappedKeyVersion(spec kmspec.KeySpec, version int) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, kv := range m.data[specKey(spec)] {
		if kv.Version == version {
			return append([]byte(nil), kv.Wrapped...), nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *memStore) DeleteWrappedKey(spec kmspec.KeySpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := specKey(spec)
	if _, ok := m.data[key]; !ok {
		return store.ErrNotFound
	}
	delete(m.data, key)
	return nil
}

func (m *memStore) ListKeySpecs() ([]kmspec.KeySpec, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
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

// --- test setup ------------------------------------------------------------

func setupHandler() http.Handler {
	ms := newMemStore()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	svc := service.NewKMSService(ms, masterKey)
	return NewHandler(svc)
}

// --- tests for POST /v1/kms/keys -------------------------------------------

func TestHandleKeys(t *testing.T) {
	handler := setupHandler()

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
			body:       `{"key_id":"foo","purpose":"encrypt","algorithm":"AES-256-GCM"}`,
			wantStatus: http.StatusCreated,
			wantResp: map[string]string{
				"key_id":    "foo",
				"purpose":   "encrypt",
				"algorithm": "AES-256-GCM",
			},
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
			body:       `{"purpose":"encrypt","algorithm":"AES-256-GCM"}`,
			wantStatus: http.StatusBadRequest,
			wantResp:   map[string]string{"error": "key_id, purpose, and algorithm are required"},
		},
		{
			name:       "Missing purpose",
			method:     http.MethodPost,
			url:        "/v1/kms/keys",
			body:       `{"key_id":"foo","algorithm":"AES-256-GCM"}`,
			wantStatus: http.StatusBadRequest,
			wantResp:   map[string]string{"error": "key_id, purpose, and algorithm are required"},
		},
		{
			name:       "Missing algorithm",
			method:     http.MethodPost,
			url:        "/v1/kms/keys",
			body:       `{"key_id":"foo","purpose":"encrypt"}`,
			wantStatus: http.StatusBadRequest,
			wantResp:   map[string]string{"error": "key_id, purpose, and algorithm are required"},
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
		t.Run(tc.name, func(t *testing.T) {
			var buf *bytes.Buffer
			if tc.body != "" {
				buf = bytes.NewBufferString(tc.body)
			} else {
				buf = &bytes.Buffer{}
			}
			req := httptest.NewRequest(tc.method, tc.url, buf)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("%s: expected status %d, got %d", tc.name, tc.wantStatus, w.Code)
			}
			var resp map[string]string
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("%s: decode error: %v", tc.name, err)
			}
			for k, v := range tc.wantResp {
				if got := resp[k]; got != v {
					t.Errorf("%s: want resp[%q]=%q, got %q", tc.name, k, v, got)
				}
			}
		})
	}
}

// --- tests for key lifecycle under /v1/kms/keys/{keyID}/{purpose}/{algorithm} ---

func TestHandleKeyBySpec(t *testing.T) {
	handler := setupHandler()

	// pre-create "foo|encrypt|AES-256-GCM"
	{
		body := `{"key_id":"foo","purpose":"encrypt","algorithm":"AES-256-GCM"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/kms/keys", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("setup: create foo expected 201, got %d", w.Code)
		}
	}

	base := "/v1/kms/keys/foo/encrypt/AES-256-GCM"
	cases := []struct {
		name         string
		method, url  string
		wantStatus   int
		wantContains string
	}{
		{
			name:         "Get existing key",
			method:       http.MethodGet,
			url:          base,
			wantStatus:   http.StatusOK,
			wantContains: `"key_versions"`,
		},
		{
			name:         "Get missing key",
			method:       http.MethodGet,
			url:          "/v1/kms/keys/bar/encrypt/AES-256-GCM",
			wantStatus:   http.StatusNotFound,
			wantContains: `"error"`,
		},
		{
			name:       "Rotate existing key",
			method:     http.MethodPost,
			url:        base + "/rotate",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Rotate missing key",
			method:     http.MethodPost,
			url:        "/v1/kms/keys/baz/encrypt/AES-256-GCM/rotate",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "Recreate existing key",
			method:     http.MethodPost,
			url:        base + "/recreate",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "Recreate missing key",
			method:     http.MethodPost,
			url:        "/v1/kms/keys/baz/encrypt/AES-256-GCM/recreate",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "Delete existing key",
			method:     http.MethodDelete,
			url:        base,
			wantStatus: http.StatusNoContent,
		},
		{
			name:         "Delete missing key",
			method:       http.MethodDelete,
			url:          "/v1/kms/keys/bar/encrypt/AES-256-GCM",
			wantStatus:   http.StatusNotFound,
			wantContains: `"error"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.url, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("%s: expected status %d, got %d", tc.name, tc.wantStatus, w.Code)
			}
			if tc.wantContains != "" && !strings.Contains(w.Body.String(), tc.wantContains) {
				t.Errorf("%s: expected body to contain %q, got %q",
					tc.name, tc.wantContains, w.Body.String())
			}
		})
	}
}
