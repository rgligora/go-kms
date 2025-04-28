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

const (
	encryptPurpose = "encrypt"
	signPurpose    = "sign"
	aesAlgo        = "AES-256-GCM"
	rsaAlgo        = "RSA-4096"
)

// bootstrapIntegration sets up an in-memory SQLite store, a real KMSService,
// and returns the HTTP handler under test.
func bootstrapIntegration(t *testing.T) http.Handler {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// Create tables SQLiteStore expects
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS metadata (
			key TEXT PRIMARY KEY,
			value BLOB NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS keys (
			key_id         TEXT    NOT NULL,
			version        INTEGER NOT NULL,
			wrapped_key    BLOB    NOT NULL,
			last_version_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (key_id, version)
		);`,
		`CREATE TABLE IF NOT EXISTS keys_metadata (
			key_id    TEXT PRIMARY KEY,
			purpose   TEXT NOT NULL,
			algorithm TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}

	st := store.NewSQLiteStore(db)

	// Initialize master key salt
	salt, err := cryptoutil.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if err := st.SetMasterKeySalt(salt); err != nil {
		t.Fatalf("set salt: %v", err)
	}

	pass := []byte("integration-pass")
	mk := cryptoutil.DeriveMasterKey(pass, salt)
	cryptoutil.Zeroize(pass)

	svc := service.NewKMSService(st, mk)
	return handlers.NewHandler(svc)
}

func TestIntegrationEndToEnd(t *testing.T) {
	h := bootstrapIntegration(t)
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := srv.Client()

	// Helper to read entire body
	readBody := func(res *http.Response) string {
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}

	// 1) LIST empty
	t.Run("ListEmpty", func(t *testing.T) {
		res, err := client.Get(srv.URL + "/v1/kms/keys")
		if err != nil {
			t.Fatalf("GET /v1/kms/keys: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var list []interface{}
		if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("expected empty list, got %v", list)
		}
	})

	// 2) CREATE two keys: one for encrypt, one for sign
	var encKeyID, signKeyID string

	t.Run("CreateEncryptKey", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"purpose":   encryptPurpose,
			"algorithm": aesAlgo,
		})
		res, err := client.Post(srv.URL+"/v1/kms/keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/kms/keys encrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", res.StatusCode, readBody(res))
		}
		var resp struct {
			KeyID     string `json:"key_id"`
			Purpose   string `json:"purpose"`
			Algorithm string `json:"algorithm"`
			Version   int    `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode create encrypt key: %v", err)
		}
		if resp.Purpose != encryptPurpose || resp.Algorithm != aesAlgo || resp.Version != 1 {
			t.Errorf("unexpected encrypt create resp: %+v", resp)
		}
		encKeyID = resp.KeyID
	})

	t.Run("CreateSignKey", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"purpose":   signPurpose,
			"algorithm": rsaAlgo,
		})
		res, err := client.Post(srv.URL+"/v1/kms/keys", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST /v1/kms/keys sign: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", res.StatusCode, readBody(res))
		}
		var resp struct {
			KeyID     string `json:"key_id"`
			Purpose   string `json:"purpose"`
			Algorithm string `json:"algorithm"`
			Version   int    `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode create sign key: %v", err)
		}
		if resp.Purpose != signPurpose || resp.Algorithm != rsaAlgo || resp.Version != 1 {
			t.Errorf("unexpected sign create resp: %+v", resp)
		}
		signKeyID = resp.KeyID
	})

	// 3) LIST now has two keys
	t.Run("ListTwo", func(t *testing.T) {
		res, err := client.Get(srv.URL + "/v1/kms/keys")
		if err != nil {
			t.Fatalf("GET /v1/kms/keys: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var list []struct {
			KeyID   string `json:"key_id"`
			Purpose string `json:"purpose"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("expected 2 keys, got %d", len(list))
		}
	})

	// 4) GET each key
	t.Run("GetEncryptKey", func(t *testing.T) {
		res, err := client.Get(srv.URL + "/v1/kms/keys/" + encKeyID)
		if err != nil {
			t.Fatalf("GET encrypt key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp struct {
			KeyID   string `json:"key_id"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode get encrypt key: %v", err)
		}
		if resp.KeyID != encKeyID || resp.Version != 1 {
			t.Errorf("unexpected get encrypt key resp: %+v", resp)
		}
	})

	t.Run("GetSignKey", func(t *testing.T) {
		res, err := client.Get(srv.URL + "/v1/kms/keys/" + signKeyID)
		if err != nil {
			t.Fatalf("GET sign key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp struct {
			KeyID   string `json:"key_id"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode get sign key: %v", err)
		}
		if resp.KeyID != signKeyID || resp.Version != 1 {
			t.Errorf("unexpected get sign key resp: %+v", resp)
		}
	})

	// 5) ENCRYPT/DECRYPT flow
	const plaintext = "integration-test"
	b64pt := base64.StdEncoding.EncodeToString([]byte(plaintext))
	var ciphertext string

	t.Run("EncryptValid", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    encKeyID,
			"plaintext": b64pt,
		})
		res, err := client.Post(srv.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp map[string]string
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode encrypt resp: %v", err)
		}
		ciphertext = resp["ciphertext"]
		if _, err := base64.StdEncoding.DecodeString(ciphertext); err != nil {
			t.Fatalf("invalid base64 ciphertext: %v", err)
		}
	})

	t.Run("EncryptInvalidJSON", func(t *testing.T) {
		res, _ := client.Post(srv.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader([]byte(`{bad`)))
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", res.StatusCode)
		}
	})

	t.Run("DecryptValid", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":     encKeyID,
			"ciphertext": ciphertext,
		})
		res, err := client.Post(srv.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp map[string]string
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode decrypt resp: %v", err)
		}
		if resp["plaintext"] != b64pt {
			t.Errorf("got %q; want %q", resp["plaintext"], b64pt)
		}
	})

	t.Run("DecryptInvalidBase64", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":     encKeyID,
			"ciphertext": "notbase64!",
		})
		res, _ := client.Post(srv.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(reqBody))
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", res.StatusCode)
		}
	})

	// 6) SIGN/VERIFY flow
	var signature string

	t.Run("SignValid", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":  signKeyID,
			"message": b64pt,
		})
		res, err := client.Post(srv.URL+"/v1/kms/sign", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp map[string]string
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode sign resp: %v", err)
		}
		signature = resp["signature"]
		if _, err := base64.StdEncoding.DecodeString(signature); err != nil {
			t.Fatalf("invalid base64 signature: %v", err)
		}
	})

	t.Run("VerifyValid", func(t *testing.T) {
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    signKeyID,
			"message":   b64pt,
			"signature": signature,
		})
		res, err := client.Post(srv.URL+"/v1/kms/verify", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp struct {
			Valid bool `json:"valid"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode verify resp: %v", err)
		}
		if !resp.Valid {
			t.Errorf("expected valid=true, got false")
		}
	})

	t.Run("VerifyBadSignature", func(t *testing.T) {
		bad := signature[:len(signature)-1] + "A"
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    signKeyID,
			"message":   b64pt,
			"signature": bad,
		})
		res, _ := client.Post(srv.URL+"/v1/kms/verify", "application/json", bytes.NewReader(reqBody))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp struct {
			Valid bool   `json:"valid"`
			Error string `json:"error"`
		}
		json.NewDecoder(res.Body).Decode(&resp)
		if resp.Valid || resp.Error == "" {
			t.Errorf("expected valid=false and error, got %+v", resp)
		}
	})

	// 7) ROTATE encrypt key and test v2 encrypt/decrypt
	t.Run("RotateEncryptKey", func(t *testing.T) {
		res, err := client.Post(srv.URL+"/v1/kms/keys/"+encKeyID+"/rotate", "application/json", nil)
		if err != nil {
			t.Fatalf("rotate encrypt key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var resp struct {
			Version int `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode rotate resp: %v", err)
		}
		if resp.Version != 2 {
			t.Errorf("expected version=2, got %d", resp.Version)
		}
		// encrypt under v2
		plain2 := "v2-data"
		b64p2 := base64.StdEncoding.EncodeToString([]byte(plain2))
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    encKeyID,
			"plaintext": b64p2,
		})
		r2, err := client.Post(srv.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("encrypt v2: %v", err)
		}
		defer r2.Body.Close()
		if r2.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", r2.StatusCode)
		}
		var r2resp map[string]string
		json.NewDecoder(r2.Body).Decode(&r2resp)
		ct2 := r2resp["ciphertext"]
		// decrypt v2
		reqBody2, _ := json.Marshal(map[string]string{
			"key_id":     encKeyID,
			"ciphertext": ct2,
		})
		d2, err := client.Post(srv.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(reqBody2))
		if err != nil {
			t.Fatalf("decrypt v2: %v", err)
		}
		defer d2.Body.Close()
		if d2.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", d2.StatusCode)
		}
		var d2resp map[string]string
		json.NewDecoder(d2.Body).Decode(&d2resp)
		if d2resp["plaintext"] != b64p2 {
			t.Errorf("v2 decrypt got %q; want %q", d2resp["plaintext"], b64p2)
		}
	})

	// 8) RECREATE encrypt key => new keyID, old fails, new works
	var newEncID string
	t.Run("RecreateEncryptKey", func(t *testing.T) {
		res, err := client.Post(srv.URL+"/v1/kms/keys/"+encKeyID+"/recreate", "application/json", nil)
		if err != nil {
			t.Fatalf("recreate encrypt key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("expected 201, got %d", res.StatusCode)
		}
		var resp struct {
			KeyID   string `json:"key_id"`
			Version int    `json:"version"`
		}
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			t.Fatalf("decode recreate resp: %v", err)
		}
		if resp.Version != 1 {
			t.Errorf("expected version=1, got %d", resp.Version)
		}
		if resp.KeyID == "" || resp.KeyID == encKeyID {
			t.Errorf("expected new key_id, got %q", resp.KeyID)
		}
		newEncID = resp.KeyID
	})

	t.Run("OldEncryptKeyGone", func(t *testing.T) {
		res, _ := client.Get(srv.URL + "/v1/kms/keys/" + encKeyID)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 for old keyID, got %d", res.StatusCode)
		}
	})

	t.Run("NewEncryptKeyWorks", func(t *testing.T) {
		// encrypt/decrypt one last time under newEncID
		b64pt2 := base64.StdEncoding.EncodeToString([]byte("fresh"))
		reqBody, _ := json.Marshal(map[string]string{
			"key_id":    newEncID,
			"plaintext": b64pt2,
		})
		res, err := client.Post(srv.URL+"/v1/kms/encrypt", "application/json", bytes.NewReader(reqBody))
		if err != nil {
			t.Fatalf("encrypt new key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}
		var encResp map[string]string
		json.NewDecoder(res.Body).Decode(&encResp)
		ct := encResp["ciphertext"]
		// decrypt
		reqBody2, _ := json.Marshal(map[string]string{
			"key_id":     newEncID,
			"ciphertext": ct,
		})
		res2, err := client.Post(srv.URL+"/v1/kms/decrypt", "application/json", bytes.NewReader(reqBody2))
		if err != nil {
			t.Fatalf("decrypt new key: %v", err)
		}
		defer res2.Body.Close()
		if res2.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res2.StatusCode)
		}
		var decResp map[string]string
		json.NewDecoder(res2.Body).Decode(&decResp)
		if decResp["plaintext"] != b64pt2 {
			t.Errorf("decrypt new key got %q; want %q", decResp["plaintext"], b64pt2)
		}
	})

	// 9) DELETE new encrypt key
	t.Run("DeleteEncryptKey", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/v1/kms/keys/"+newEncID, nil)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("delete new key: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", res.StatusCode)
		}
	})

	t.Run("GetAfterDeleteRecreated", func(t *testing.T) {
		res, _ := client.Get(srv.URL + "/v1/kms/keys/" + newEncID)
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("expected 404 after deletion, got %d", res.StatusCode)
		}
	})
}
