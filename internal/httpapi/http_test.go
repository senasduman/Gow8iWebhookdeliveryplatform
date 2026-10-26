package httpapi

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modexa/webhook-delivery-platform/internal/config"
	"github.com/modexa/webhook-delivery-platform/internal/store"
)

func TestProtectedManagementEndpointsRejectMissingCredentials(t *testing.T) {
	api := New(nil, config.Config{}, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/v1/api-keys", nil)
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "missing bearer API key") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateOrganizationRejectsInvalidInput(t *testing.T) {
	api := New(nil, config.Config{BootstrapToken: "expected"}, slog.Default())
	req := httptest.NewRequest(http.MethodPost, "/v1/bootstrap/organization", strings.NewReader(`{"name":"","key_name":"initial"}`))
	req.Header.Set("X-Bootstrap-Token", "expected")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBootstrapRejectsMissingOrInvalidToken(t *testing.T) {
	api := New(nil, config.Config{BootstrapToken: "expected"}, slog.Default())
	for _, token := range []string{"", "wrong"} {
		req := httptest.NewRequest(http.MethodPost, "/v1/bootstrap/organization", strings.NewReader(`{"name":"Acme","key_name":"initial"}`))
		if token != "" {
			req.Header.Set("X-Bootstrap-Token", token)
		}
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("token=%q status=%d body=%s", token, rec.Code, rec.Body.String())
		}
	}
}

func TestEndpointURLValidation(t *testing.T) {
	for _, test := range []struct {
		raw string
		ok  bool
	}{{"https://example.com/hooks", true}, {"http://example.com/hooks", false}, {"https://", false}, {"https://example.com/a\nb", false}} {
		if got := validURL(test.raw); got != test.ok {
			t.Errorf("validURL(%q)=%v, want %v", test.raw, got, test.ok)
		}
	}
}

func TestSensitiveValuesAreNotIncludedInManagementResponses(t *testing.T) {
	key := store.APIKey{ID: uuid.New(), Name: "test", CreatedAt: time.Now()}
	if response := apiKeyResponse(key, ""); response["key"] != nil {
		t.Fatal("API key listing response exposed the secret")
	}
	endpoint := store.WebhookEndpoint{ID: uuid.New(), URL: "https://example.com", Secret: "secret-value"}
	if response := endpointResponse(endpoint); response["secret"] != nil {
		t.Fatal("endpoint response exposed the secret")
	}
}
