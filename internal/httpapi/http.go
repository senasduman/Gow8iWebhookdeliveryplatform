package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/modexa/webhook-delivery-platform/internal/config"
	"github.com/modexa/webhook-delivery-platform/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type API struct {
	db     *store.Store
	cfg    config.Config
	logger *slog.Logger
}

func New(db *store.Store, cfg config.Config, logger *slog.Logger) http.Handler {
	a := &API{db: db, cfg: cfg, logger: logger}
	r := chi.NewRouter()
	r.Use(requestID, a.auth)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", a.ready)
	r.Handle("/metrics", promhttp.Handler())
	r.Post("/v1/bootstrap/organization", a.createOrganization)
	r.Get("/v1/organization", a.getOrganization)
	r.Post("/v1/api-keys", a.createAPIKey)
	r.Get("/v1/api-keys", a.listAPIKeys)
	r.Delete("/v1/api-keys/{keyID}", a.revokeAPIKey)
	r.Post("/v1/webhook-endpoints", a.createEndpoint)
	r.Get("/v1/webhook-endpoints", a.listEndpoints)
	r.Patch("/v1/webhook-endpoints/{endpointID}", a.updateEndpoint)
	r.Delete("/v1/webhook-endpoints/{endpointID}", a.deleteEndpoint)
	r.Post("/v1/events", a.createEvent)
	return r
}
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

type requestIDKey struct{}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/metrics" || r.URL.Path == "/v1/bootstrap/organization" {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
			writeError(w, 401, "missing bearer API key")
			return
		}
		org, err := a.db.Authenticate(r.Context(), key[len(prefix):], a.cfg.APIKeyPepper)
		if err != nil {
			writeError(w, 401, "invalid API key")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), orgKey{}, org)))
	})
}

type orgKey struct{}

func orgFrom(ctx context.Context) uuid.UUID { return ctx.Value(orgKey{}).(uuid.UUID) }
func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	if err := a.db.DB.Ping(r.Context()); err != nil {
		writeError(w, 503, "database unavailable")
		return
	}
	w.WriteHeader(200)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}
func (a *API) createEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Type == "" || store.ValidatePayload(req.Data) != nil {
		writeError(w, 400, "type and non-empty data are required")
		return
	}
	idem := r.Header.Get("Idempotency-Key")
	if idem == "" {
		writeError(w, 400, "Idempotency-Key is required")
		return
	}
	event, exists, err := a.db.CreateEvent(r.Context(), orgFrom(r.Context()), req.Type, req.Data, idem)
	if err != nil {
		a.logger.Error("create event failed", "error", err)
		writeError(w, 500, "could not create event")
		return
	}
	if !exists {
		if err := a.db.Enqueue(r.Context(), orgFrom(r.Context()), event.ID); err != nil {
			a.logger.Error("enqueue event failed", "error", err)
			writeError(w, 500, "could not enqueue event")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": event.ID, "status": "queued"})
}
func (a *API) createOrganization(w http.ResponseWriter, r *http.Request) {
	if a.cfg.BootstrapToken == "" {
		writeError(w, http.StatusNotFound, "bootstrap is disabled")
		return
	}
	if !secureTokenEqual(r.Header.Get("X-Bootstrap-Token"), a.cfg.BootstrapToken) {
		writeError(w, http.StatusUnauthorized, "invalid bootstrap credentials")
		return
	}
	var req struct {
		Name    string `json:"name"`
		KeyName string `json:"key_name"`
	}
	if !decodeJSON(w, r, &req) || req.Name == "" || len(req.Name) > 200 || req.KeyName == "" || len(req.KeyName) > 100 {
		writeError(w, http.StatusBadRequest, "name and key_name are required and have valid lengths")
		return
	}
	org, key, rawKey, err := a.db.CreateOrganization(r.Context(), req.Name, req.KeyName, a.cfg.APIKeyPepper)
	if err != nil {
		if errors.Is(err, store.ErrBootstrapConsumed) {
			writeError(w, http.StatusConflict, "bootstrap has already been consumed")
			return
		}
		a.logger.Error("create organization failed", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create organization")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"organization": organizationResponse(org), "api_key": apiKeyResponse(key, rawKey)})
}
func secureTokenEqual(got, expected string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}
func (a *API) getOrganization(w http.ResponseWriter, r *http.Request) {
	org, err := a.db.GetOrganization(r.Context(), orgFrom(r.Context()))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, organizationResponse(org))
}
func (a *API) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) || req.Name == "" || len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, "name is required and must be at most 100 characters")
		return
	}
	key, rawKey, err := a.db.CreateAPIKey(r.Context(), orgFrom(r.Context()), req.Name, a.cfg.APIKeyPepper)
	if err != nil {
		a.logger.Error("create API key failed", "error", err)
		writeError(w, 500, "could not create API key")
		return
	}
	writeJSON(w, http.StatusCreated, apiKeyResponse(key, rawKey))
}
func (a *API) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.db.ListAPIKeys(r.Context(), orgFrom(r.Context()))
	if err != nil {
		a.logger.Error("list API keys failed", "error", err)
		writeError(w, 500, "could not list API keys")
		return
	}
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		result = append(result, apiKeyResponse(key, ""))
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": result})
}
func (a *API) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		writeError(w, 400, "invalid key ID")
		return
	}
	if err = a.db.RevokeAPIKey(r.Context(), orgFrom(r.Context()), keyID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) createEndpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if !decodeJSON(w, r, &req) || !validURL(req.URL) || len(req.Secret) < 16 || len(req.Secret) > 512 {
		writeError(w, 400, "url must be an HTTPS URL and secret must be between 16 and 512 characters")
		return
	}
	endpoint, err := a.db.CreateEndpoint(r.Context(), orgFrom(r.Context()), req.URL, req.Secret)
	if err != nil {
		a.logger.Error("create endpoint failed", "error", err)
		writeError(w, 500, "could not create endpoint")
		return
	}
	writeJSON(w, 201, endpointResponse(endpoint))
}
func (a *API) listEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := a.db.ListEndpoints(r.Context(), orgFrom(r.Context()))
	if err != nil {
		a.logger.Error("list endpoints failed", "error", err)
		writeError(w, 500, "could not list endpoints")
		return
	}
	result := make([]map[string]any, 0, len(endpoints))
	for _, endpoint := range endpoints {
		result = append(result, endpointResponse(endpoint))
	}
	writeJSON(w, 200, map[string]any{"webhook_endpoints": result})
}
func (a *API) updateEndpoint(w http.ResponseWriter, r *http.Request) {
	endpointID, err := uuid.Parse(chi.URLParam(r, "endpointID"))
	if err != nil {
		writeError(w, 400, "invalid endpoint ID")
		return
	}
	var req struct {
		URL    *string `json:"url"`
		Secret *string `json:"secret"`
		Active *bool   `json:"active"`
	}
	if !decodeJSON(w, r, &req) || (req.URL == nil && req.Secret == nil && req.Active == nil) {
		writeError(w, 400, "at least one field is required")
		return
	}
	if req.URL != nil && !validURL(*req.URL) {
		writeError(w, 400, "url must be an HTTPS URL")
		return
	}
	if req.Secret != nil && (len(*req.Secret) < 16 || len(*req.Secret) > 512) {
		writeError(w, 400, "secret must be between 16 and 512 characters")
		return
	}
	endpoint, err := a.db.UpdateEndpoint(r.Context(), orgFrom(r.Context()), endpointID, req.URL, req.Secret, req.Active)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, endpointResponse(endpoint))
}
func (a *API) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	endpointID, err := uuid.Parse(chi.URLParam(r, "endpointID"))
	if err != nil {
		writeError(w, 400, "invalid endpoint ID")
		return
	}
	if err = a.db.DeleteEndpoint(r.Context(), orgFrom(r.Context()), endpointID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, 400, "invalid JSON request")
		return false
	}
	return true
}
func validURL(raw string) bool {
	parsed, err := url.ParseRequestURI(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && !strings.ContainsAny(raw, "\r\n")
}
func organizationResponse(org store.Organization) map[string]any {
	return map[string]any{"id": org.ID, "name": org.Name, "created_at": org.CreatedAt}
}
func apiKeyResponse(key store.APIKey, raw string) map[string]any {
	result := map[string]any{"id": key.ID, "name": key.Name, "created_at": key.CreatedAt}
	if key.RevokedAt != nil {
		result["revoked_at"] = key.RevokedAt
	}
	if raw != "" {
		result["key"] = raw
	}
	return result
}
func endpointResponse(endpoint store.WebhookEndpoint) map[string]any {
	return map[string]any{"id": endpoint.ID, "url": endpoint.URL, "active": endpoint.Active, "created_at": endpoint.CreatedAt}
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "database operation failed")
}
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
