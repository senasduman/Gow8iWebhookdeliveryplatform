package signing

import (
	"testing"
	"time"
)

func TestSignAndVerifyExactBody(t *testing.T) {
	timestamp := time.Unix(1730000000, 0).UTC()
	body := []byte(`{"order_id":"123"}`)
	signature := Sign("secret", timestamp, body)
	if err := Verify("secret", signature, timestamp, body, timestamp.Add(10*time.Second), 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := Verify("secret", signature, timestamp, []byte(`{"order_id":"124"}`), timestamp, 5*time.Minute); err == nil {
		t.Fatal("modified payload accepted")
	}
	if err := Verify("wrong", signature, timestamp, body, timestamp, 5*time.Minute); err == nil {
		t.Fatal("invalid secret accepted")
	}
}

func TestVerifyRejectsMissingMalformedAndExpiredSignatures(t *testing.T) {
	now := time.Unix(1730000000, 0).UTC()
	body := []byte("body")
	tests := []struct {
		name      string
		signature string
		timestamp time.Time
	}{
		{"missing", "", now},
		{"malformed", "v2=abc", now},
		{"expired", Sign("secret", now.Add(-6*time.Minute), body), now.Add(-6 * time.Minute)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Verify("secret", test.signature, test.timestamp, body, now, 5*time.Minute); err == nil {
				t.Fatal("invalid signature was accepted")
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	parsed, err := ParseTimestamp("1730000000")
	if err != nil || parsed.Unix() != 1730000000 {
		t.Fatalf("parsed=%v err=%v", parsed, err)
	}
	if _, err := ParseTimestamp("not-a-timestamp"); err == nil {
		t.Fatal("malformed timestamp accepted")
	}
}
