package store

import (
	"strings"
	"testing"
	"time"
)

func TestHashKeyIsDeterministicAndPepperBound(t *testing.T) {
	first := HashKey("wk_test", "pepper-a")
	if first != HashKey("wk_test", "pepper-a") {
		t.Fatal("same key and pepper must produce the same hash")
	}
	if first == HashKey("wk_test", "pepper-b") {
		t.Fatal("different peppers must produce different hashes")
	}
	if len(first) != 64 || strings.Trim(first, "0123456789abcdef") != "" {
		t.Fatalf("expected a SHA-256 hex hash, got %q", first)
	}
}

func TestBackoffIsExponentialAndCapped(t *testing.T) {
	if got := backoff(1); got != time.Second {
		t.Fatalf("attempt 1: got %s", got)
	}
	if got := backoff(3); got != 4*time.Second {
		t.Fatalf("attempt 3: got %s", got)
	}
	if got := backoff(9); got != 128*time.Second {
		t.Fatalf("attempt 9 should be capped at attempt 8: got %s", got)
	}
}

func TestValidatePayload(t *testing.T) {
	if err := ValidatePayload(nil); err == nil {
		t.Fatal("empty payload should be rejected")
	}
	if err := ValidatePayload([]byte(`{"order_id":"123"}`)); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
}
