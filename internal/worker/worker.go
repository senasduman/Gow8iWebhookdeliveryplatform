package worker

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/modexa/webhook-delivery-platform/internal/config"
	"github.com/modexa/webhook-delivery-platform/internal/signing"
	"github.com/modexa/webhook-delivery-platform/internal/store"
)

type Worker struct {
	db     *store.Store
	cfg    config.Config
	logger *slog.Logger
	client *http.Client
}

func New(db *store.Store, cfg config.Config, logger *slog.Logger) *Worker {
	return &Worker{db: db, cfg: cfg, logger: logger, client: &http.Client{Timeout: cfg.DeliveryTimeout}}
}
func (w *Worker) Run(ctx context.Context) {
	for i := 0; i < w.cfg.WorkerCount; i++ {
		go w.loop(ctx)
	}
	<-ctx.Done()
}
func (w *Worker) loop(ctx context.Context) {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		w.process(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (w *Worker) process(ctx context.Context) {
	rows, err := w.db.Claim(ctx, w.cfg.WorkerCount)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id, eventID, endpointID uuid.UUID
		var attempts int
		var typ string
		var payload, secretCiphertext []byte
		var url string
		if err := rows.Scan(&id, &eventID, &endpointID, &attempts, &typ, &payload, &url, &secretCiphertext); err != nil {
			continue
		}
		secret, err := w.db.DecryptSecret(secretCiphertext)
		if err != nil {
			_ = w.db.Finish(ctx, id, attempts, "failed", 0, "webhook secret unavailable", w.cfg.MaxAttempts)
			continue
		}
		w.deliver(ctx, id, eventID, endpointID, attempts, typ, payload, url, secret)
	}
}
func (w *Worker) deliver(ctx context.Context, id, eventID, endpointID uuid.UUID, attempts int, typ string, payload []byte, url, secret string) {
	statusCode, responseBody, err := w.sendDelivery(ctx, id, eventID, typ, payload, url, secret)
	if err != nil {
		_ = w.db.Finish(ctx, id, attempts, "failed", 0, err.Error(), w.cfg.MaxAttempts)
		return
	}
	status := "failed"
	if statusCode >= 200 && statusCode < 300 {
		status = "delivered"
	}
	_ = w.db.Finish(ctx, id, attempts, status, statusCode, responseBody, w.cfg.MaxAttempts)
}

func (w *Worker) sendDelivery(ctx context.Context, id, eventID uuid.UUID, typ string, payload []byte, url, secret string) (int, string, error) {
	req, err := w.newDeliveryRequest(ctx, id, eventID, typ, payload, url, secret)
	if err != nil {
		return 0, "", err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(body), nil
}

func (w *Worker) newDeliveryRequest(ctx context.Context, id, eventID uuid.UUID, typ string, payload []byte, url, secret string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Event-Type", typ)
	req.Header.Set("X-Event-ID", eventID.String())
	req.Header.Set("X-Delivery-ID", id.String())
	timestamp := time.Now().UTC()
	req.Header.Set(signing.TimestampHeader, strconv.FormatInt(timestamp.Unix(), 10))
	req.Header.Set(signing.SignatureHeader, signing.Sign(secret, timestamp, payload))
	if w.cfg.LegacySecretHeader {
		req.Header.Set("X-Webhook-Secret", secret)
	}
	return req, nil
}
