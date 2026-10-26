package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modexa/webhook-delivery-platform/internal/signing"
	"net/http"
	"net/http/httptest"
)

func TestReceiverRejectsInvalidDeliveryRequests(t *testing.T) {
	now := time.Unix(1730000000, 0).UTC()
	receiver := &Receiver{secret: "secret", tolerance: 5 * time.Minute, now: func() time.Time { return now }}
	body := []byte(`{"order_id":"123"}`)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signature := signing.Sign("secret", now, body)
	tests := []struct {
		name  string
		body  string
		sig   string
		stamp string
		want  int
	}{
		{"missing delivery id", string(body), signature, timestamp, http.StatusBadRequest},
		{"altered payload", `{"order_id":"999"}`, signature, timestamp, http.StatusUnauthorized},
		{"invalid signature", string(body), "v1=deadbeef", timestamp, http.StatusUnauthorized},
		{"expired timestamp", string(body), signing.Sign("secret", now.Add(-6*time.Minute), []byte(string(body))), strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10), http.StatusUnauthorized},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			req.Header.Set("X-Event-Type", "order.created")
			req.Header.Set("X-Webhook-Timestamp", test.stamp)
			req.Header.Set("X-Webhook-Signature", test.sig)
			if test.name != "missing delivery id" {
				req.Header.Set("X-Delivery-ID", uuid.NewString())
			}
			rec := httptest.NewRecorder()
			receiver.ServeHTTP(rec, req)
			if rec.Code != test.want {
				t.Fatalf("status=%d body=%s want=%d", rec.Code, rec.Body.String(), test.want)
			}
		})
	}
}

func TestReceiverDeduplicatesAtomicallyWithPostgres(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set DATABASE_URL to run receiver PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema, err := os.ReadFile(filepath.Join(".", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, string(schema)); err != nil {
		t.Fatal(err)
	}
	deliveryID := uuid.New()
	body := []byte(`{"order_id":"123"}`)
	now := time.Now().UTC()
	receiver := NewReceiver(db, "secret", 5*time.Minute)
	receiver.now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
		req.Header.Set("X-Delivery-ID", deliveryID.String())
		req.Header.Set("X-Event-Type", "order.created")
		req.Header.Set(signing.TimestampHeader, strconv.FormatInt(now.Unix(), 10))
		req.Header.Set(signing.SignatureHeader, signing.Sign("secret", now, body))
		rec := httptest.NewRecorder()
		receiver.ServeHTTP(rec, req)
		want := http.StatusOK
		if rec.Code != want {
			t.Fatalf("attempt %d status=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	var deliveries, events int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM receiver_deliveries WHERE delivery_id=$1`, deliveryID).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM receiver_events WHERE delivery_id=$1`, deliveryID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || events != 1 {
		t.Fatalf("deliveries=%d events=%d, want one of each", deliveries, events)
	}
}
