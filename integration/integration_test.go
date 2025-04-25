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

// bootstrapIntegration now returns both the HTTP handler and the service
func bootstrapIntegration(t *testing.T) (http.Handler, *service.KMSService) {
	t.Helper()

	// 1) In-memory SQLite with the right schema
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
			key_id      TEXT NOT NULL,
			version     INTEGER NOT NULL,
			wrapped_key BLOB    NOT NULL,
			created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
		);`,
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
	cryptoutil.Zeroize(passphrase)

	// 3) Service + Handler
	svc := service.NewKMSService(st, masterKey)
	h := handlers.NewHandler(svc)

	// 4) Wire routes
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux, svc
}

func TestFullIntegrationFlow(t *testing.T) {
	handler, svc := bootstrapIntegration(t)
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()

	const keyID = "alpha"
	const plaintext = "hello, integration!"
	b64pt := base64.StdEncoding.EncodeToString([]byte(plaintext))

	// 1) Create key
	t.Run("GenerateKey", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"key_id": keyID})
		res, err := client.Post(server.URL+"/v1/kms/keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/kms/keys: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 201 Created, got %d: %s", res.StatusCode, string(b))
		}
	})

	var v1Ciphertext string

	// 2) Encrypt under v1
	t.Run("EncryptDataV1", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    keyID,
			"plaintext": b64pt,
		})
		res, err := client.Post(server.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST /v1/kms/encrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, string(b))
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
			"key_id":     keyID,
			"ciphertext": v1Ciphertext,
		})
		res, err := client.Post(server.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST /v1/kms/decrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, string(b))
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
			t.Fatalf("decrypted %q; want %q", string(decoded), plaintext)
		}
	})

	// 4) GET wrapped key
	t.Run("GetWrappedKey", func(t *testing.T) {
		res, err := client.Get(server.URL + "/v1/kms/keys/" + keyID)
		if err != nil {
			t.Fatalf("GET /v1/kms/keys/%s: %v", keyID, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, string(b))
		}
		var resp struct {
			WrappedKeys []string `json:"wrapped_keys"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode get response: %v", err)
		}
		if len(resp.WrappedKeys) != 1 {
			t.Fatalf("expected 1 wrapped key, got %d", len(resp.WrappedKeys))
		}
	})

	// 5) DELETE key
	t.Run("DeleteKey", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, server.URL+"/v1/kms/keys/"+keyID, nil)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("DELETE /v1/kms/keys/%s: %v", keyID, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 204 No Content, got %d: %s", res.StatusCode, string(b))
		}
	})

	// 6) GET after delete => 404
	t.Run("GetAfterDelete", func(t *testing.T) {
		res, err := client.Get(server.URL + "/v1/kms/keys/" + keyID)
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
		res, err := client.Post(server.URL+"/v1/kms/keys/"+keyID+"/recreate", "application/json", nil)
		if err != nil {
			t.Fatalf("POST /v1/kms/keys/%s/recreate: %v", keyID, err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 404 Not Found, got %d: %s", res.StatusCode, string(b))
		}
	})

	// 7b) RECREATE key which exists
	t.Run("RecreateExistingKey", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"key_id": keyID})
		_, err := client.Post(server.URL+"/v1/kms/keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/kms/keys: %v", err)
		}

		resRECREATE, errRECREATE := client.Post(server.URL+"/v1/kms/keys/"+keyID+"/recreate", "application/json", nil)
		if errRECREATE != nil {
			t.Fatalf("POST /v1/kms/keys/%s/recreate: %v", keyID, err)
		}
		defer resRECREATE.Body.Close()
		if resRECREATE.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resRECREATE.Body)
			t.Fatalf("expected 201 Created, got %d: %s", resRECREATE.StatusCode, string(b))
		}
	})

	// 8) GET after recreate => 200 + one wrapped key
	t.Run("GetAfterRecreate", func(t *testing.T) {
		res, err := client.Get(server.URL + "/v1/kms/keys/" + keyID)
		if err != nil {
			t.Fatalf("GET after recreate: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, string(b))
		}
		var resp struct {
			WrappedKeys []string `json:"wrapped_keys"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode get after recreate: %v", err)
		}
		if len(resp.WrappedKeys) != 1 {
			t.Fatalf("expected 1 wrapped key after recreate, got %d", len(resp.WrappedKeys))
		}
	})

	// 9a) Encrypt under v1 of the RECREATED key
	t.Run("EncryptDataWithRecreatedV1", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    keyID,
			"plaintext": b64pt,
		})
		res, err := client.Post(server.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("POST /v1/kms/encrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("expected 200 OK, got %d: %s", res.StatusCode, string(b))
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

	// 9b) Rotate to v2, ensure old-v1 ciphertext still decrypts and new encrypt/decrypt works
	t.Run("RotateAndEncrypt", func(t *testing.T) {
		// Rotate the DEK to version 2
		if err := svc.RotateKey(keyID); err != nil {
			t.Fatalf("RotateKey: %v", err)
		}

		// 9a) Decrypt the original v1 ciphertext
		oldReq, _ := json.Marshal(map[string]string{
			"key_id":     keyID,
			"ciphertext": v1Ciphertext,
		})
		oldRes, err := client.Post(server.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(oldReq))
		if err != nil {
			t.Fatalf("decrypt v1 after rotate: %v", err)
		}
		defer oldRes.Body.Close()
		if oldRes.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(oldRes.Body)
			t.Fatalf("expected 200 OK, got %d: %s", oldRes.StatusCode, string(b))
		}
		var oldResp struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(oldRes.Body).Decode(&oldResp); err != nil {
			t.Fatalf("decode old decrypt response: %v", err)
		}
		decodedOld, err := base64.StdEncoding.DecodeString(oldResp.Plaintext)
		if err != nil {
			t.Fatalf("old plaintext not valid base64: %v", err)
		}
		if string(decodedOld) != plaintext {
			t.Fatalf("v1 ciphertext decrypted to %q; want %q", string(decodedOld), plaintext)
		}

		// 9b) Encrypt & decrypt a new message under v2
		newPlain := "still works under v2"
		b64New := base64.StdEncoding.EncodeToString([]byte(newPlain))

		encReq, _ := json.Marshal(map[string]string{
			"key_id":    keyID,
			"plaintext": b64New,
		})
		encRes, err := client.Post(server.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(encReq))
		if err != nil {
			t.Fatalf("encrypt under v2: %v", err)
		}
		defer encRes.Body.Close()
		if encRes.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(encRes.Body)
			t.Fatalf("expected 200 OK on v2 encrypt, got %d: %s", encRes.StatusCode, string(b))
		}
		var encResp struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(encRes.Body).Decode(&encResp); err != nil {
			t.Fatalf("decode v2 encrypt response: %v", err)
		}

		decReq, _ := json.Marshal(map[string]string{
			"key_id":     keyID,
			"ciphertext": encResp.Ciphertext,
		})
		decRes, err := client.Post(server.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(decReq))
		if err != nil {
			t.Fatalf("decrypt under v2: %v", err)
		}
		defer decRes.Body.Close()
		if decRes.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(decRes.Body)
			t.Fatalf("expected 200 OK on v2 decrypt, got %d: %s", decRes.StatusCode, string(b))
		}
		var decResp struct {
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(decRes.Body).Decode(&decResp); err != nil {
			t.Fatalf("decode v2 decrypt response: %v", err)
		}
		decodedNew, err := base64.StdEncoding.DecodeString(decResp.Plaintext)
		if err != nil {
			t.Fatalf("new plaintext not valid base64: %v", err)
		}
		if string(decodedNew) != newPlain {
			t.Fatalf("v2 ciphertext decrypted to %q; want %q", string(decodedNew), newPlain)
		}
	})
}
