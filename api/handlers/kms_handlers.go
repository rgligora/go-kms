package handlers

import (
	"encoding/base64"
	"encoding/json"
	"github.com/go-chi/chi/v5/middleware"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rgligora/go-kms/internal/kmspec"
	"github.com/rgligora/go-kms/internal/service"
)

// Handler wraps your KMSService.
type Handler struct {
	Svc *service.KMSService
}

// NewHandler wires up all routes.
func NewHandler(svc *service.KMSService) http.Handler {
	h := &Handler{Svc: svc}
	r := chi.NewRouter()

	r.Use(middleware.StripSlashes)

	// Return JSON error on unsupported methods
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})

	// ── Key lifecycle (REST CRUD) ─────────────────────────────────────────────
	r.Get("/v1/kms/keys", h.listKeys)
	r.Post("/v1/kms/keys", h.createKey)

	r.Route("/v1/kms/keys/{keyID}", func(r chi.Router) {
		r.Get("/", h.getKey)
		r.Delete("/", h.deleteKey)
		r.Post("/rotate", h.rotateKey)
		r.Post("/recreate", h.recreateKey)
	})

	// ── Data operations (RPC style) ───────────────────────────────────────────
	r.Post("/v1/kms/encrypt", h.encryptData)
	r.Post("/v1/kms/decrypt", h.decryptData)
	r.Post("/v1/kms/sign", h.signData)
	r.Post("/v1/kms/verify", h.verifyData)

	return r
}

// writeJSON writes v as JSON with given status
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ── Handlers ────────────────────────────────────────────────────────────

// listKeys -> GET /v1/kms/keys
func (h *Handler) listKeys(w http.ResponseWriter, r *http.Request) {
	out, err := h.Svc.ListKeys()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// createKey -> POST /v1/kms/keys
// body: { "purpose": "...", "algorithm": "..." }
func (h *Handler) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Purpose   kmspec.KeyPurpose   `json:"purpose"`
		Algorithm kmspec.KeyAlgorithm `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	info, err := h.Svc.CreateKey(req.Purpose, req.Algorithm)
	if err != nil {
		if err == service.ErrKeyAlreadyExists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

// getKey -> GET /v1/kms/keys/{keyID}
func (h *Handler) getKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	info, err := h.Svc.GetKey(keyID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// deleteKey -> DELETE /v1/kms/keys/{keyID}
func (h *Handler) deleteKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	if err := h.Svc.DeleteKey(keyID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateKey -> POST /v1/kms/keys/{keyID}/rotate
func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	info, err := h.Svc.RotateKey(keyID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// recreateKey -> POST /v1/kms/keys/{keyID}/recreate
func (h *Handler) recreateKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	info, err := h.Svc.RecreateKey(keyID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

// encryptData -> POST /v1/kms/encrypt
// body: { "key_id":"…", "plaintext":"BASE64…" }
func (h *Handler) encryptData(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID     string `json:"key_id"`
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	pt, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plaintext not valid base64"})
		return
	}
	ct, err := h.Svc.EncryptData(req.KeyID, pt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ct)})
}

// decryptData -> POST /v1/kms/decrypt
// body: { "key_id":"…", "ciphertext":"BASE64…" }
func (h *Handler) decryptData(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID      string `json:"key_id"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ciphertext not valid base64"})
		return
	}
	pt, err := h.Svc.DecryptData(req.KeyID, ct)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
}

// signData -> POST /v1/kms/sign
// body: { "key_id":"…", "message":"BASE64…" }
func (h *Handler) signData(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID   string `json:"key_id"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	msg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message not valid base64"})
		return
	}
	sig, err := h.Svc.SignData(req.KeyID, msg)
	if err != nil {
		// NotFound ⇒ 404, else 500
		code := http.StatusInternalServerError
		if err == service.ErrKeyNotFound {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
}

// verifyData -> POST /v1/kms/verify
// body: { "key_id":"…", "message":"BASE64…", "signature":"BASE64…" }
func (h *Handler) verifyData(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID     string `json:"key_id"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	msg, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message not valid base64"})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signature not valid base64"})
		return
	}
	if err := h.Svc.VerifySignature(req.KeyID, msg, sig); err != nil {
		// invalid signature: still 200 but valid=false
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}
