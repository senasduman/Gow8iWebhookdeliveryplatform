package store

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	DB  *pgxpool.Pool
	box cipher.AEAD
}
type Endpoint struct {
	ID     uuid.UUID
	URL    string
	Secret string
}
type Event struct {
	ID      uuid.UUID
	Type    string
	Payload []byte
}
type Organization struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
}
type APIKey struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
	RevokedAt *time.Time
}
type WebhookEndpoint struct {
	ID        uuid.UUID
	URL       string
	Secret    string
	Active    bool
	CreatedAt time.Time
}

var ErrBootstrapConsumed = errors.New("bootstrap already consumed")

func Open(ctx context.Context, url, encryptionKey string) (*Store, error) {
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		return nil, err
	}
	box, err := newSecretBox(encryptionKey)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db, box: box}, nil
}
func (s *Store) Close() { s.DB.Close() }
func HashKey(key, pepper string) string {
	sum := sha256.Sum256([]byte(pepper + ":" + key))
	return hex.EncodeToString(sum[:])
}
func GenerateAPIKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate API key: %w", err)
	}
	return "wk_live_" + hex.EncodeToString(raw), nil
}
func (s *Store) CreateOrganization(ctx context.Context, name, keyName, pepper string) (Organization, APIKey, string, error) {
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return Organization{}, APIKey{}, "", err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Organization{}, APIKey{}, "", err
	}
	defer tx.Rollback(ctx)
	var consumed bool
	if err := tx.QueryRow(ctx, `SELECT consumed FROM bootstrap_state WHERE id=1 FOR UPDATE`).Scan(&consumed); err != nil {
		return Organization{}, APIKey{}, "", err
	}
	if consumed {
		return Organization{}, APIKey{}, "", ErrBootstrapConsumed
	}
	var org Organization
	if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ($1) RETURNING id,name,created_at`, name).
		Scan(&org.ID, &org.Name, &org.CreatedAt); err != nil {
		return Organization{}, APIKey{}, "", err
	}
	var key APIKey
	if err := tx.QueryRow(ctx, `INSERT INTO api_keys (organization_id,key_hash,name) VALUES ($1,$2,$3) RETURNING id,name,created_at`,
		org.ID, HashKey(rawKey, pepper), keyName).Scan(&key.ID, &key.Name, &key.CreatedAt); err != nil {
		return Organization{}, APIKey{}, "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE bootstrap_state SET consumed=true,consumed_at=now() WHERE id=1`); err != nil {
		return Organization{}, APIKey{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return Organization{}, APIKey{}, "", err
	}
	return org, key, rawKey, nil
}
func (s *Store) GetOrganization(ctx context.Context, orgID uuid.UUID) (Organization, error) {
	var org Organization
	err := s.DB.QueryRow(ctx, `SELECT id,name,created_at FROM organizations WHERE id=$1`, orgID).
		Scan(&org.ID, &org.Name, &org.CreatedAt)
	return org, err
}
func (s *Store) CreateAPIKey(ctx context.Context, orgID uuid.UUID, name, pepper string) (APIKey, string, error) {
	rawKey, err := GenerateAPIKey()
	if err != nil {
		return APIKey{}, "", err
	}
	var key APIKey
	err = s.DB.QueryRow(ctx, `INSERT INTO api_keys (organization_id,key_hash,name) VALUES ($1,$2,$3) RETURNING id,name,created_at`,
		orgID, HashKey(rawKey, pepper), name).Scan(&key.ID, &key.Name, &key.CreatedAt)
	return key, rawKey, err
}
func (s *Store) ListAPIKeys(ctx context.Context, orgID uuid.UUID) ([]APIKey, error) {
	rows, err := s.DB.Query(ctx, `SELECT id,name,created_at,revoked_at FROM api_keys WHERE organization_id=$1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []APIKey
	for rows.Next() {
		var key APIKey
		if err := rows.Scan(&key.ID, &key.Name, &key.CreatedAt, &key.RevokedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
func (s *Store) RevokeAPIKey(ctx context.Context, orgID, keyID uuid.UUID) error {
	tag, err := s.DB.Exec(ctx, `UPDATE api_keys SET revoked_at=COALESCE(revoked_at,now()) WHERE organization_id=$1 AND id=$2`, orgID, keyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
func (s *Store) CreateEndpoint(ctx context.Context, orgID uuid.UUID, url, secret string) (WebhookEndpoint, error) {
	ciphertext, err := s.encryptSecret(secret)
	if err != nil {
		return WebhookEndpoint{}, err
	}
	var endpoint WebhookEndpoint
	err = s.DB.QueryRow(ctx, `INSERT INTO webhook_endpoints (organization_id,url,secret_ciphertext) VALUES ($1,$2,$3) RETURNING id,url,active,created_at`,
		orgID, url, ciphertext).Scan(&endpoint.ID, &endpoint.URL, &endpoint.Active, &endpoint.CreatedAt)
	return endpoint, err
}
func (s *Store) ListEndpoints(ctx context.Context, orgID uuid.UUID) ([]WebhookEndpoint, error) {
	rows, err := s.DB.Query(ctx, `SELECT id,url,active,created_at FROM webhook_endpoints WHERE organization_id=$1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var endpoints []WebhookEndpoint
	for rows.Next() {
		var endpoint WebhookEndpoint
		if err := rows.Scan(&endpoint.ID, &endpoint.URL, &endpoint.Active, &endpoint.CreatedAt); err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, rows.Err()
}
func (s *Store) UpdateEndpoint(ctx context.Context, orgID, endpointID uuid.UUID, url *string, secret *string, active *bool) (WebhookEndpoint, error) {
	var ciphertext []byte
	var err error
	if secret != nil {
		ciphertext, err = s.encryptSecret(*secret)
		if err != nil {
			return WebhookEndpoint{}, err
		}
	}
	var endpoint WebhookEndpoint
	err = s.DB.QueryRow(ctx, `UPDATE webhook_endpoints SET url=COALESCE($3,url),secret_ciphertext=COALESCE($4,secret_ciphertext),active=COALESCE($5,active)
		WHERE organization_id=$1 AND id=$2 RETURNING id,url,active,created_at`, orgID, endpointID, url, ciphertext, active).
		Scan(&endpoint.ID, &endpoint.URL, &endpoint.Active, &endpoint.CreatedAt)
	return endpoint, err
}
func (s *Store) DeleteEndpoint(ctx context.Context, orgID, endpointID uuid.UUID) error {
	tag, err := s.DB.Exec(ctx, `DELETE FROM webhook_endpoints WHERE organization_id=$1 AND id=$2`, orgID, endpointID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
func (s *Store) Authenticate(ctx context.Context, key, pepper string) (uuid.UUID, error) {
	var orgID uuid.UUID
	err := s.DB.QueryRow(ctx, `SELECT organization_id FROM api_keys WHERE key_hash=$1 AND revoked_at IS NULL`, HashKey(key, pepper)).Scan(&orgID)
	return orgID, err
}
func (s *Store) CreateEvent(ctx context.Context, orgID uuid.UUID, eventType string, payload []byte, idem string) (Event, bool, error) {
	var event Event
	err := s.DB.QueryRow(ctx, `INSERT INTO events (organization_id,event_type,payload,idempotency_key) VALUES ($1,$2,$3,$4)
		ON CONFLICT (organization_id,idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key
		RETURNING id,event_type,payload`, orgID, eventType, payload, idem).Scan(&event.ID, &event.Type, &event.Payload)
	if err != nil {
		return Event{}, false, err
	}
	var count int
	err = s.DB.QueryRow(ctx, `SELECT COUNT(*) FROM deliveries WHERE event_id=$1`, event.ID).Scan(&count)
	return event, count > 0, err
}
func (s *Store) Enqueue(ctx context.Context, orgID, eventID uuid.UUID) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO deliveries (organization_id,event_id,endpoint_id,status,next_attempt_at)
		SELECT $1,$2,id,'pending',now() FROM webhook_endpoints WHERE organization_id=$1 AND active=true`, orgID, eventID)
	return err
}
func (s *Store) Endpoints(ctx context.Context, orgID uuid.UUID) ([]Endpoint, error) {
	rows, err := s.DB.Query(ctx, `SELECT id,url,secret_ciphertext FROM webhook_endpoints WHERE organization_id=$1 AND active=true`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Endpoint
	for rows.Next() {
		var e Endpoint
		var ciphertext []byte
		if err := rows.Scan(&e.ID, &e.URL, &ciphertext); err != nil {
			return nil, err
		}
		e.Secret, err = s.decryptSecret(ciphertext)
		if err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
func (s *Store) Claim(ctx context.Context, limit int) (pgx.Rows, error) {
	return s.DB.Query(ctx, `WITH claimed AS (
		SELECT id FROM deliveries WHERE status IN ('pending','retrying') AND next_attempt_at <= now()
		ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT $1
	) UPDATE deliveries d SET status='processing',attempts=d.attempts+1,updated_at=now()
		FROM claimed WHERE d.id=claimed.id
		RETURNING d.id,d.event_id,d.endpoint_id,d.attempts,
			(SELECT event_type FROM events WHERE id=d.event_id),
			(SELECT payload FROM events WHERE id=d.event_id),
			(SELECT url FROM webhook_endpoints WHERE id=d.endpoint_id),
			(SELECT secret_ciphertext FROM webhook_endpoints WHERE id=d.endpoint_id)`, limit)
}
func (s *Store) Finish(ctx context.Context, id uuid.UUID, attempts int, status string, code int, body string, max int) error {
	next := time.Now().Add(backoff(attempts))
	if status == "delivered" || attempts >= max {
		_, err := s.DB.Exec(ctx, `UPDATE deliveries SET status=$2,http_status=$3,response_body=$4,completed_at=now(),updated_at=now() WHERE id=$1`, id, status, code, body)
		return err
	}
	_, err := s.DB.Exec(ctx, `UPDATE deliveries SET status='retrying',http_status=$2,response_body=$3,next_attempt_at=$4,updated_at=now() WHERE id=$1`, id, code, body, next)
	return err
}
func backoff(attempt int) time.Duration {
	if attempt > 8 {
		attempt = 8
	}
	return time.Duration(1<<uint(attempt-1)) * time.Second
}
func ValidatePayload(payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("payload must not be empty")
	}
	return nil
}
