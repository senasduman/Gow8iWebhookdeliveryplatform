package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/modexa/webhook-delivery-platform/internal/signing"
)

type Receiver struct {
	db        *pgxpool.Pool
	secret    string
	tolerance time.Duration
	now       func() time.Time
}

func NewReceiver(db *pgxpool.Pool, secret string, tolerance time.Duration) *Receiver {
	return &Receiver{db: db, secret: secret, tolerance: tolerance, now: time.Now}
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	deliveryID := req.Header.Get("X-Delivery-ID")
	if deliveryID == "" {
		http.Error(w, "missing X-Delivery-ID", http.StatusBadRequest)
		return
	}
	timestampValue := req.Header.Get(signing.TimestampHeader)
	timestamp, err := signing.ParseTimestamp(timestampValue)
	if err != nil {
		http.Error(w, "invalid webhook timestamp", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		http.Error(w, "could not read request body", http.StatusBadRequest)
		return
	}
	if err := signing.Verify(r.secret, req.Header.Get(signing.SignatureHeader), timestamp, body, r.now(), r.tolerance); err != nil {
		http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
		return
	}
	eventType := req.Header.Get("X-Event-Type")
	if eventType == "" {
		http.Error(w, "missing X-Event-Type", http.StatusBadRequest)
		return
	}
	if err := r.processAtomically(req.Context(), deliveryID, eventType, body); err != nil {
		if errors.Is(err, errDuplicateDelivery) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"duplicate"}`))
			return
		}
		http.Error(w, "could not process webhook", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"processed"}`))
}

var errDuplicateDelivery = errors.New("duplicate delivery")

func (r *Receiver) processAtomically(ctx context.Context, deliveryID, eventType string, body []byte) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var inserted bool
	err = tx.QueryRow(ctx, `INSERT INTO receiver_deliveries (delivery_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING true`, deliveryID).Scan(&inserted)
	if errors.Is(err, pgx.ErrNoRows) {
		return errDuplicateDelivery
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO receiver_events (delivery_id,event_type,payload) VALUES ($1,$2,$3)`, deliveryID, eventType, body); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	secret := os.Getenv("RECEIVER_WEBHOOK_SECRET")
	if databaseURL == "" || secret == "" {
		slog.Error("DATABASE_URL and RECEIVER_WEBHOOK_SECRET are required")
		os.Exit(1)
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		slog.Error("receiver database connection failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	if err := db.Ping(ctx); err != nil {
		slog.Error("receiver database ping failed", "error", err)
		os.Exit(1)
	}
	handler := NewReceiver(db, secret, 5*time.Minute)
	slog.Info("receiver listening", "addr", ":8090")
	if err := http.ListenAndServe(":8090", handler); err != nil {
		slog.Error("receiver stopped", "error", err)
	}
}
