package integration

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rgligora/go-kms/api/handlers"
	"github.com/rgligora/go-kms/internal/cryptoutil"
	"github.com/rgligora/go-kms/internal/service"
	"github.com/rgligora/go-kms/internal/store"
)

const (
	keyID     = "alpha"
	purpose   = "encrypt"
	algorithm = "AES-256-GCM"
)

// bootstrapIntegration returns an HTTP handler with an in-memory sqlite instance.
func bootstrapIntegration(t *testing.T) http.Handler {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("opening in-memory sqlite: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS metadata (
			key   TEXT PRIMARY KEY,
			value BLOB NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS keys (
			key_id      TEXT    NOT NULL,
			purpose     TEXT    NOT NULL,
			algorithm   TEXT    NOT NULL,
			version     INTEGER NOT NULL,
			wrapped_key BLOB    NOT NULL,
			created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, purpose, algorithm, version)
		);`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("creating table: %v", err)
		}
	}

	st := store.NewSQLiteStore(db)
	salt, err := cryptoutil.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if err := st.SetMasterKeySalt(salt); err != nil {
		t.Fatalf("set salt: %v", err)
	}
	passphrase := []byte("test-integration-pass")
	masterKey := cryptoutil.DeriveMasterKey(passphrase, salt)
	cryptoutil.Zeroize(passphrase)

	svc := service.NewKMSService(st, masterKey)
	return handlers.NewHandler(svc)
}

func TestFullIntegrationFlow(t *testing.T) {
	handler := bootstrapIntegration(t)
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()

	const plaintext = "hello, integration!"
	b64pt := base64.StdEncoding.EncodeToString([]byte(plaintext))

	// 1) Create key
	t.Run("GenerateKey", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"key_id":    keyID,
			"purpose":   purpose,
			"algorithm": algorithm,
		})
		res, err := client.Post(server.URL+"/v1/kms/keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/kms/keys: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 201 Created, got %d: %s", res.StatusCode, b)
		}
	})

	var v1Ciphertext string

	// 2) Encrypt under v1
	t.Run("EncryptDataV1", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"data": b64pt,
		})
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/encrypt", server.URL, keyID, purpose, algorithm)
		res, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST encrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, b)
		}
		var resp struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode encrypt response: %v", err)
		}
		if resp.Ciphertext == "" {
			t.Fatal("empty ciphertext")
		}
		v1Ciphertext = resp.Ciphertext
	})

	// 3) Decrypt under v1
	t.Run("DecryptDataV1", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"data": v1Ciphertext,
		})
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/decrypt", server.URL, keyID, purpose, algorithm)
		res, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST decrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, b)
		}
		var resp struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode decrypt response: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		if err != nil {
			t.Fatalf("plaintext not valid base64: %v", err)
		}
		if string(decoded) != plaintext {
			t.Fatalf("decrypted %q; want %q", decoded, plaintext)
		}
	})

	// 4) GET wrapped key
	t.Run("GetWrappedKey", func(t *testing.T) {
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s", server.URL, keyID, purpose, algorithm)
		res, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET wrapped key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, b)
		}
		var resp struct {
			KeyVersions []struct {
				Version int    `json:"version"`
				Wrapped string `json:"wrapped"`
			} `json:"key_versions"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode get response: %v", err)
		}
		if len(resp.KeyVersions) != 1 {
			t.Fatalf("expected 1 wrapped key, got %d", len(resp.KeyVersions))
		}
	})

	// 5) DELETE key
	t.Run("DeleteKey", func(t *testing.T) {
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s", server.URL, keyID, purpose, algorithm)
		req, _ := http.NewRequest(http.MethodDelete, url, nil)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("DELETE key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 204 No Content, got %d: %s", res.StatusCode, b)
		}
	})

	// 6) GET after delete => 404
	t.Run("GetAfterDelete", func(t *testing.T) {
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s", server.URL, keyID, purpose, algorithm)
		res, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET after delete: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 Not Found, got %d", res.StatusCode)
		}
	})

	// 7a) RECREATE key which does not exist
	t.Run("RecreateMissingKey", func(t *testing.T) {
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/recreate", server.URL, keyID, purpose, algorithm)
		res, err := client.Post(url, "application/json", nil)
		if err != nil {
			t.Fatalf("POST recreate missing: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 404 Not Found, got %d: %s", res.StatusCode, b)
		}
	})

	// 7b) RECREATE key which exists
	t.Run("RecreateExistingKey", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"key_id":    keyID,
			"purpose":   purpose,
			"algorithm": algorithm,
		})
		_, err := client.Post(server.URL+"/v1/kms/keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST create for recreate: %v", err)
		}

		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/recreate", server.URL, keyID, purpose, algorithm)
		res, err := client.Post(url, "application/json", nil)
		if err != nil {
			t.Fatalf("POST recreate existing: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 201 Created, got %d: %s", res.StatusCode, b)
		}
	})

	// 8) GET after recreate => 200 + one wrapped key
	t.Run("GetAfterRecreate", func(t *testing.T) {
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s", server.URL, keyID, purpose, algorithm)
		res, err := client.Get(url)
		if err != nil {
			t.Fatalf("GET after recreate: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, b)
		}
		var resp struct {
			KeyVersions []struct {
				Version int    `json:"version"`
				Wrapped string `json:"wrapped"`
			} `json:"key_versions"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode get after recreate: %v", err)
		}
		if len(resp.KeyVersions) != 1 {
			t.Fatalf("expected 1 wrapped key after recreate, got %d", len(resp.KeyVersions))
		}
	})

	// 9a) Encrypt under v1 of the RECREATED key
	t.Run("EncryptDataWithRecreatedV1", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"data": b64pt,
		})
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/encrypt", server.URL, keyID, purpose, algorithm)
		res, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST encrypt v1 recreated: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, b)
		}
		var resp struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode encrypt response: %v", err)
		}
		if resp.Ciphertext == "" {
			t.Fatal("empty ciphertext")
		}
		v1Ciphertext = resp.Ciphertext
	})

	// 9b) Rotate to v2, then decrypt v1 and encrypt/decrypt under v2
	t.Run("RotateAndEncrypt", func(t *testing.T) {
		// rotate
		url := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/rotate", server.URL, keyID, purpose, algorithm)
		res, err := client.Post(url, "application/json", nil)
		if err != nil {
			t.Fatalf("POST rotate: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, b)
		}

		// decrypt original v1
		oldReq, _ := json.Marshal(map[string]string{"data": v1Ciphertext})
		oldURL := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/decrypt", server.URL, keyID, purpose, algorithm)
		oldRes, err := client.Post(oldURL, "application/json", bytes.NewReader(oldReq))
		if err != nil {
			t.Fatalf("decrypt v1 after rotate: %v", err)
		}
		defer oldRes.Body.Close()
		if oldRes.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(oldRes.Body)
			t.Fatalf("expected 200 OK, got %d: %s", oldRes.StatusCode, b)
		}
		var oldResp struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(oldRes.Body).Decode(&oldResp); err != nil {
			t.Fatalf("decode old decrypt response: %v", err)
		}
		decodedOld, _ := base64.StdEncoding.DecodeString(oldResp.Plaintext)
		if string(decodedOld) != plaintext {
			t.Fatalf("v1 decrypted to %q; want %q", decodedOld, plaintext)
		}

		// encrypt under v2
		newPlain := "still works under v2"
		b64New := base64.StdEncoding.EncodeToString([]byte(newPlain))
		encReqBody, _ := json.Marshal(map[string]string{"data": b64New})
		encURL := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/encrypt", server.URL, keyID, purpose, algorithm)
		encRes, err := client.Post(encURL, "application/json", bytes.NewReader(encReqBody))
		if err != nil {
			t.Fatalf("encrypt under v2: %v", err)
		}
		defer encRes.Body.Close()
		if encRes.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(encRes.Body)
			t.Fatalf("expected 200 OK on v2 encrypt, got %d: %s", encRes.StatusCode, b)
		}
		var encResp struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(encRes.Body).Decode(&encResp); err != nil {
			t.Fatalf("decode v2 encrypt response: %v", err)
		}

		// decrypt under v2
		decReqBody, _ := json.Marshal(map[string]string{"data": encResp.Ciphertext})
		decURL := fmt.Sprintf("%s/v1/kms/keys/%s/%s/%s/decrypt", server.URL, keyID, purpose, algorithm)
		decRes, err := client.Post(decURL, "application/json", bytes.NewReader(decReqBody))
		if err != nil {
			t.Fatalf("decrypt under v2: %v", err)
		}
		defer decRes.Body.Close()
		if decRes.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(decRes.Body)
			t.Fatalf("expected 200 OK on v2 decrypt, got %d: %s", decRes.StatusCode, b)
		}
		var decResp struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(decRes.Body).Decode(&decResp); err != nil {
			t.Fatalf("decode v2 decrypt response: %v", err)
		}
		decodedNew, _ := base64.StdEncoding.DecodeString(decResp.Plaintext)
		if string(decodedNew) != newPlain {
			t.Fatalf("v2 decrypted to %q; want %q", decodedNew, newPlain)
		}
	})
}
