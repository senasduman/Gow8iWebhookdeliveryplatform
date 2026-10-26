package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestManagementOperationsPostgres(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	for _, name := range []string{"001_init.up.sql", "002_bootstrap_state.up.sql"} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if _, err := db.DB.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", name, err)
		}
	}
	orgA, initialKey, rawKey, err := db.CreateOrganization(ctx, "integration-a-"+uuid.NewString(), "initial", "integration-pepper")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	if rawKey == "" || initialKey.ID == uuid.Nil {
		t.Fatal("initial API key was not returned")
	}
	if _, err := db.Authenticate(ctx, "invalid-key", "integration-pepper"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("invalid credential error=%v, want pgx.ErrNoRows", err)
	}
	if _, _, _, err := db.CreateOrganization(ctx, "integration-b-"+uuid.NewString(), "initial", "integration-pepper"); !errors.Is(err, ErrBootstrapConsumed) {
		t.Fatalf("bootstrap reuse error=%v, want ErrBootstrapConsumed", err)
	}
	var orgB Organization
	if err := db.DB.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ($1) RETURNING id,name,created_at`, "integration-b-"+uuid.NewString()).
		Scan(&orgB.ID, &orgB.Name, &orgB.CreatedAt); err != nil {
		t.Fatalf("create second organization fixture: %v", err)
	}
	key, _, err := db.CreateAPIKey(ctx, orgA.ID, "worker", "integration-pepper")
	if err != nil {
		t.Fatalf("create API key: %v", err)
	}
	keys, err := db.ListAPIKeys(ctx, orgA.ID)
	if err != nil || len(keys) != 2 {
		t.Fatalf("list keys: len=%d err=%v", len(keys), err)
	}
	if err := db.RevokeAPIKey(ctx, orgA.ID, key.ID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if _, err := db.GetOrganization(ctx, orgB.ID); err != nil {
		t.Fatalf("get organization: %v", err)
	}
	endpoint, err := db.CreateEndpoint(ctx, orgA.ID, "https://example.com/webhook", "integration-secret-1234")
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	var ciphertext []byte
	if err := db.DB.QueryRow(ctx, `SELECT secret_ciphertext FROM webhook_endpoints WHERE id=$1`, endpoint.ID).Scan(&ciphertext); err != nil {
		t.Fatalf("read endpoint ciphertext: %v", err)
	}
	if string(ciphertext) == "integration-secret-1234" {
		t.Fatal("webhook secret was stored as plaintext")
	}
	if decrypted, err := db.DecryptSecret(ciphertext); err != nil || decrypted != "integration-secret-1234" {
		t.Fatalf("decrypt endpoint secret: value=%q err=%v", decrypted, err)
	}
	corrupted := append([]byte(nil), ciphertext...)
	corrupted[len(corrupted)-1] ^= 0xff
	if _, err := db.DecryptSecret(corrupted); err == nil {
		t.Fatal("corrupted webhook secret ciphertext decrypted successfully")
	}
	if _, err := db.UpdateEndpoint(ctx, orgA.ID, endpoint.ID, nil, nil, boolPtr(false)); err != nil {
		t.Fatalf("update endpoint: %v", err)
	}
	endpoints, err := db.ListEndpoints(ctx, orgA.ID)
	if err != nil || len(endpoints) != 1 || endpoints[0].Active {
		t.Fatalf("list/update endpoints: len=%d active=%v err=%v", len(endpoints), endpoints[0].Active, err)
	}
	if _, err := db.UpdateEndpoint(ctx, orgA.ID, endpoint.ID, nil, nil, boolPtr(true)); err != nil {
		t.Fatalf("reactivate endpoint for retry test: %v", err)
	}
	if _, err := db.UpdateEndpoint(ctx, orgB.ID, endpoint.ID, nil, nil, boolPtr(true)); err == nil {
		t.Fatal("cross-organization update unexpectedly succeeded")
	}
	if err := db.DeleteEndpoint(ctx, orgB.ID, endpoint.ID); err == nil {
		t.Fatal("cross-organization delete unexpectedly succeeded")
	}
	event, _, err := db.CreateEvent(ctx, orgA.ID, "order.created", []byte(`{"order_id":"retry-test"}`), "retry-test-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create retry event: %v", err)
	}
	if err := db.Enqueue(ctx, orgA.ID, event.ID); err != nil {
		t.Fatalf("enqueue retry event: %v", err)
	}
	rows, err := db.Claim(ctx, 1)
	if err != nil {
		t.Fatalf("claim first attempt: %v", err)
	}
	var deliveryID, claimedEventID, claimedEndpointID uuid.UUID
	var attempts int
	var eventType string
	var payload, secretCiphertext []byte
	var endpointURL string
	if !rows.Next() || rows.Scan(&deliveryID, &claimedEventID, &claimedEndpointID, &attempts, &eventType, &payload, &endpointURL, &secretCiphertext) != nil {
		rows.Close()
		t.Fatal("first delivery claim missing")
	}
	rows.Close()
	if claimedEventID != event.ID || claimedEndpointID != endpoint.ID || attempts != 1 {
		t.Fatalf("first claim delivery=%s event=%s endpoint=%s attempts=%d", deliveryID, claimedEventID, claimedEndpointID, attempts)
	}
	if err := db.Finish(ctx, deliveryID, attempts, "failed", 500, "temporary", 3); err != nil {
		t.Fatalf("finish failed attempt: %v", err)
	}
	if _, err := db.DB.Exec(ctx, `UPDATE deliveries SET next_attempt_at=now() WHERE id=$1`, deliveryID); err != nil {
		t.Fatal(err)
	}
	rows, err = db.Claim(ctx, 1)
	if err != nil {
		t.Fatalf("claim retry: %v", err)
	}
	var retryID uuid.UUID
	var retryAttempts int
	if !rows.Next() || rows.Scan(&retryID, &claimedEventID, &claimedEndpointID, &retryAttempts, &eventType, &payload, &endpointURL, &secretCiphertext) != nil {
		rows.Close()
		t.Fatal("retry claim missing")
	}
	rows.Close()
	if retryID != deliveryID || retryAttempts != 2 {
		t.Fatalf("retry changed logical delivery: first=%s retry=%s attempts=%d", deliveryID, retryID, retryAttempts)
	}
	if err := db.Finish(ctx, retryID, retryAttempts, "delivered", 200, "ok", 3); err != nil {
		t.Fatalf("finish retry: %v", err)
	}
	if _, err := db.DB.Exec(ctx, `DELETE FROM deliveries WHERE endpoint_id=$1`, endpoint.ID); err != nil {
		t.Fatalf("clean retry deliveries: %v", err)
	}
	if err := db.DeleteEndpoint(ctx, orgA.ID, endpoint.ID); err != nil {
		t.Fatalf("delete endpoint: %v", err)
	}
	if err := db.DeleteEndpoint(ctx, orgA.ID, endpoint.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing endpoint error=%v, want pgx.ErrNoRows", err)
	}
}

func boolPtr(value bool) *bool { return &value }
