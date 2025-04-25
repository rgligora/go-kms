package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rgligora/go-kms/internal/store"
	"log"
	"net/http"
	"strings"

	"github.com/rgligora/go-kms/internal/service"
)

// Handler wraps KMSService for HTTP handlers.
type Handler struct {
	Service *service.KMSService
}

// NewHandler constructs a new HTTP handler.
func NewHandler(svc *service.KMSService) *Handler {
	return &Handler{Service: svc}
}

// RegisterRoutes registers KMS endpoints on the given ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/kms/keys", h.handleKeys)
	mux.HandleFunc("/v1/kms/keys/", h.handleKeyByID)
	mux.HandleFunc("/v1/kms/encrypt", h.handleEncrypt)
	mux.HandleFunc("/v1/kms/decrypt", h.handleDecrypt)
}

// JSONError writes an error response with given status code.
func JSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func logRequest(r *http.Request, msg string) {
	log.Printf("%s %s → %s", r.Method, r.URL.Path, msg)
}

// handleKeys handles POST /v1/kms/keys for key creation.
func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Parse request body
	var req struct {
		KeyID string `json:"key_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.KeyID == "" {
		JSONError(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// Generate the key
	if err := h.Service.CreateKey(req.KeyID); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	logRequest(r, "created key: "+req.KeyID)

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"key_id": req.KeyID})
}

// handleKeyByID handles:
//
//	GET    /v1/kms/keys/{keyID}
//	DELETE /v1/kms/keys/{keyID}
//	POST   /v1/kms/keys/{keyID}/rotate
//	POST   /v1/kms/keys/{keyID}/recreate
func (h *Handler) handleKeyByID(w http.ResponseWriter, r *http.Request) {
	// Strip prefix + split
	p := strings.TrimPrefix(r.URL.Path, "/v1/kms/keys/")
	parts := strings.Split(p, "/")
	keyID := parts[0]
	if keyID == "" {
		JSONError(w, http.StatusBadRequest, "key_id is required in path")
		return
	}

	// Decide which op
	switch {
	// ── GET wrapped key ───────────────────────────────────────────
	case len(parts) == 1 && r.Method == http.MethodGet:
		kvs, err := h.Service.GetWrappedKey(keyID)
		if err != nil {
			JSONError(w, http.StatusNotFound, err.Error())
			return
		}
		// build a response struct that includes version + wrapped blob
		type versionResp struct {
			Version int    `json:"version"`
			Wrapped string `json:"wrapped"` // base64
		}
		out := make([]versionResp, 0, len(kvs))
		for _, kv := range kvs {
			out = append(out, versionResp{
				Version: kv.Version,
				Wrapped: base64.StdEncoding.EncodeToString(kv.Wrapped),
			})
		}
		logRequest(r, "retrieved wrapped key versions: "+keyID)
		w.Header().Set("Content-Type", "application/json")
		// payload: { "key_versions": [ { "version":1, "wrapped":"..." }, ... ] }
		json.NewEncoder(w).Encode(map[string]interface{}{"key_versions": out})
		return

	// ── DELETE key ─────────────────────────────────────────────────
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if err := h.Service.DeleteKey(keyID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				JSONError(w, http.StatusNotFound, err.Error())
			} else {
				JSONError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		logRequest(r, "deleted key: "+keyID)
		w.WriteHeader(http.StatusNoContent)
		return

	// ── POST /rotate ─────────────────────────────────────────────
	case len(parts) == 2 && parts[1] == "rotate" && r.Method == http.MethodPost:
		err := h.Service.RotateKey(keyID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				logRequest(r, "rotate missing key: "+keyID)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			JSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		logRequest(r, "rotated key: "+keyID)
		w.WriteHeader(http.StatusOK)
		return

	// ── POST /recreate ─────────────────────────────────────────────
	case len(parts) == 2 && parts[1] == "recreate" && r.Method == http.MethodPost:
		err := h.Service.RecreateKey(keyID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				logRequest(r, "recreate missing key: "+keyID)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			JSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		logRequest(r, "recreated key: "+keyID)
		w.WriteHeader(http.StatusCreated)
		return

	default:
		JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
}

// handleEncrypt handles POST /v1/kms/encrypt
func (h *Handler) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Parse request
	var req struct {
		KeyID     string `json:"key_id"`
		Plaintext string `json:"plaintext"` // base64-encoded
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.KeyID == "" || req.Plaintext == "" {
		JSONError(w, http.StatusBadRequest, "key_id and plaintext are required")
		return
	}
	// Decode base64 plaintext
	pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "plaintext not valid base64")
		return
	}
	// Encrypt
	ct, err := h.Service.EncryptData(req.KeyID, pt)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Encode ciphertext
	enc := base64.StdEncoding.EncodeToString(ct)

	logRequest(r, "encrypted data using key: "+req.KeyID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ciphertext": enc})
}

// handleDecrypt handles POST /v1/kms/decrypt
func (h *Handler) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Parse request
	var req struct {
		KeyID      string `json:"key_id"`
		Ciphertext string `json:"ciphertext"` // base64-encoded
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		JSONError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.KeyID == "" || req.Ciphertext == "" {
		JSONError(w, http.StatusBadRequest, "key_id and ciphertext are required")
		return
	}
	// Decode base64 ciphertext
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		JSONError(w, http.StatusBadRequest, "ciphertext not valid base64")
		return
	}
	// Decrypt
	pt, err := h.Service.DecryptData(req.KeyID, ct)
	if err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Encode plaintext
	enc := base64.StdEncoding.EncodeToString(pt)

	logRequest(r, "decrypted data using key: "+req.KeyID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"plaintext": enc})
}
