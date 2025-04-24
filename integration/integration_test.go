package integration

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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

// bootstrapIntegration sets up an in-memory DB, store, service, and HTTP handler.
func bootstrapIntegration(t *testing.T) http.Handler {
	t.Helper()

	// 1) In-memory SQLite
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("opening in-memory sqlite: %v", err)
	}
	// Create tables
	for _, stmt := range []string{
		`CREATE TABLE metadata(key TEXT PRIMARY KEY, value BLOB NOT NULL);`,
		`CREATE TABLE keys(key_id TEXT PRIMARY KEY, wrapped_key BLOB NOT NULL);`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("creating table: %v", err)
		}
	}

	// 2) Prepare store + salt + masterKey
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
	cryptoutil.Zeroize(passphrase) // clean up

	// 3) Service + Handler
	svc := service.NewKMSService(st, masterKey)
	h := handlers.NewHandler(svc)

	// 4) Wire routes
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

func TestGenerateEncryptDecryptCycle(t *testing.T) {
	handler := bootstrapIntegration(t)
	server := httptest.NewServer(handler)
	defer server.Close()

	client := server.Client()

	// 1) Create a new key
	{
		reqBody := map[string]string{"key_id": "alpha"}
		b, _ := json.Marshal(reqBody)
		res, err := client.Post(server.URL+"/v1/kms/keys", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST /v1/kms/keys: %v", err)
		}
		if res.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 201, got %d: %s", res.StatusCode, string(body))
		}
	}

	// 2) Encrypt some data
	plaintext := "hello, integration!"
	b64pt := base64.StdEncoding.EncodeToString([]byte(plaintext))
	var ciphertext string
	{
		reqBody := map[string]string{
			"key_id":    "alpha",
			"plaintext": b64pt,
		}
		b, _ := json.Marshal(reqBody)
		res, err := client.Post(server.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST /v1/kms/encrypt: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(res.Body)
			t.Fatalf("encrypt status %d: %s", res.StatusCode, string(body))
		}
		var resp struct {
			Ciphertext string `json:"ciphertext"`
		}
		json.NewDecoder(res.Body).Decode(&resp)
		ciphertext = resp.Ciphertext
		if ciphertext == "" {
			t.Fatal("empty ciphertext")
		}
	}

	// 3) Decrypt and verify
	{
		reqBody := map[string]string{
			"key_id":     "alpha",
			"ciphertext": ciphertext,
		}
		b, _ := json.Marshal(reqBody)
		res, err := client.Post(server.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST /v1/kms/decrypt: %v", err)
		}
		if res.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(res.Body)
			t.Fatalf("decrypt status %d: %s", res.StatusCode, string(body))
		}
		var resp struct {
			Plaintext string `json:"plaintext"`
		}
		json.NewDecoder(res.Body).Decode(&resp)
		// decode Base64
		pt, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		if err != nil {
			t.Fatalf("invalid base64 plaintext: %v", err)
		}
		if string(pt) != plaintext {
			t.Fatalf("decrypted '%s'; expected '%s'", string(pt), plaintext)
		}
	}
}
