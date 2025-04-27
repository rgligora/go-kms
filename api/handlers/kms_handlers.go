// internal/api/kms_handlers.go
package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/rgligora/go-kms/internal/kmspec"
	"github.com/rgligora/go-kms/internal/service"
	"github.com/rgligora/go-kms/internal/store"
)

// Handler holds your KMS service.
type Handler struct {
	Svc *service.KMSService
}

// NewHandler wires up all routes and installs a JSON MethodNotAllowed.
func NewHandler(svc *service.KMSService) http.Handler {
	h := &Handler{Svc: svc}
	r := chi.NewRouter()

	// Return JSON error on unsupported methods
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	})

	// Key lifecycle
	r.Post("/v1/kms/keys", h.createKey)
	r.Route("/v1/kms/keys/{keyID}/{purpose}/{algorithm}", func(r chi.Router) {
		r.Get("/", h.getKey)
		r.Delete("/", h.deleteKey)
		r.Post("/rotate", h.rotateKey)
		r.Post("/recreate", h.recreateKey)
	})

	// Data operations
	r.Post("/v1/kms/keys/{keyID}/{purpose}/{algorithm}/encrypt", h.encryptData)
	r.Post("/v1/kms/keys/{keyID}/{purpose}/{algorithm}/decrypt", h.decryptData)
	r.Post("/v1/kms/keys/{keyID}/{purpose}/{algorithm}/sign", h.signData)
	r.Post("/v1/kms/keys/{keyID}/{purpose}/{algorithm}/verify", h.verifyData)

	return r
}

// ─── Helpers ────────────────────────────────────────────────────────────

// extractSpec builds a KeySpec from URL path parameters.
func extractSpec(r *http.Request) (kmspec.KeySpec, error) {
	keyID := chi.URLParam(r, "keyID")
	purp := chi.URLParam(r, "purpose")
	alg := chi.URLParam(r, "algorithm")
	if keyID == "" || purp == "" || alg == "" {
		return kmspec.KeySpec{}, errors.New("missing path parameters")
	}
	return kmspec.KeySpec{
		KeyID:     keyID,
		Purpose:   kmspec.KeyPurpose(purp),
		Algorithm: kmspec.KeyAlgorithm(alg),
	}, nil
}

// decodeBody decodes {"data":"BASE64…"} into a *[]byte.
func decodeBody(r *http.Request, dst interface{}) error {
	wrapper := struct{ Data string }{}
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(wrapper.Data)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	switch ptr := dst.(type) {
	case *[]byte:
		*ptr = raw
		return nil
	default:
		return fmt.Errorf("unsupported dst type %T", dst)
	}
}

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ─── Handlers ────────────────────────────────────────────────────────────

func (h *Handler) createKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyID     string `json:"key_id"`
		Purpose   string `json:"purpose"`
		Algorithm string `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	// Validate required fields
	if req.KeyID == "" || req.Purpose == "" || req.Algorithm == "" {
		writeJSON(w, http.StatusBadRequest,
			map[string]string{"error": "key_id, purpose, and algorithm are required"})
		return
	}

	spec := kmspec.KeySpec{
		KeyID:     req.KeyID,
		Purpose:   kmspec.KeyPurpose(req.Purpose),
		Algorithm: kmspec.KeyAlgorithm(req.Algorithm),
	}
	if err := h.Svc.CreateKey(spec); err != nil {
		if errors.Is(err, service.ErrKeyAlreadyExists) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"key_id":    spec.KeyID,
		"purpose":   string(spec.Purpose),
		"algorithm": string(spec.Algorithm),
	})
}

func (h *Handler) getKey(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	kvs, err := h.Svc.GetWrappedKey(spec)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	out := make([]map[string]interface{}, len(kvs))
	for i, kv := range kvs {
		out[i] = map[string]interface{}{
			"version": kv.Version,
			"wrapped": base64.StdEncoding.EncodeToString(kv.Wrapped),
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"key_versions": out})
}

func (h *Handler) deleteKey(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.Svc.DeleteKey(spec); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) rotateKey(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.Svc.RotateKey(spec); err != nil {
		if errors.Is(err, service.ErrKeyNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) recreateKey(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.Svc.RecreateKey(spec); err != nil {
		if errors.Is(err, service.ErrKeyNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) encryptData(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var plaintext []byte
	if err := decodeBody(r, &plaintext); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ct, err := h.Svc.EncryptData(spec, plaintext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ct)})
}

func (h *Handler) decryptData(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var ciphertext []byte
	if err := decodeBody(r, &ciphertext); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	pt, err := h.Svc.DecryptDataWithSpec(spec, ciphertext)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)})
}

func (h *Handler) signData(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var message []byte
	if err := decodeBody(r, &message); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	sig, err := h.Svc.SignData(spec, message)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"signature": base64.StdEncoding.EncodeToString(sig)})
}

func (h *Handler) verifyData(w http.ResponseWriter, r *http.Request) {
	spec, err := extractSpec(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var req struct {
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
	if err := h.Svc.VerifySignature(spec, msg, sig); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
}
