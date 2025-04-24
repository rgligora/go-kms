package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"path"

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
	mux.HandleFunc("/v1/kms/keys/", h.handleGetKeyByID)
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
	if err := h.Service.GenerateKey(req.KeyID); err != nil {
		JSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	logRequest(r, "created key: "+req.KeyID)

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"key_id": req.KeyID})
}

// handleGetKeyByID handles GET /v1/kms/keys/{id} to return the wrapped key.
func (h *Handler) handleGetKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		JSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Extract key ID from URL
	keyID := path.Base(r.URL.Path)
	if keyID == "" {
		JSONError(w, http.StatusBadRequest, "key_id is required in path")
		return
	}

	// Load wrapped key
	wrapped, err := h.Service.GetWrappedKey(keyID)
	if err != nil {
		JSONError(w, http.StatusNotFound, err.Error())
		return
	}
	// Base64-encode for JSON transport
	enc := base64.StdEncoding.EncodeToString(wrapped)

	logRequest(r, "retrieved wrapped key: "+keyID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"wrapped_key": enc})
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
