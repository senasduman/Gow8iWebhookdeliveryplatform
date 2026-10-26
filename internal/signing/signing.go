package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	SignatureHeader = "X-Webhook-Signature"
	TimestampHeader = "X-Webhook-Timestamp"
	Version         = "v1"
)

func Sign(secret string, timestamp time.Time, body []byte) string {
	message := signingMessage(timestamp, body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(message)
	return Version + "=" + hex.EncodeToString(mac.Sum(nil))
}

func Verify(secret, signature string, timestamp time.Time, body []byte, now time.Time, tolerance time.Duration) error {
	if tolerance <= 0 {
		return fmt.Errorf("timestamp tolerance must be positive")
	}
	if timestamp.IsZero() || now.Sub(timestamp) > tolerance || timestamp.Sub(now) > tolerance {
		return fmt.Errorf("timestamp outside allowed window")
	}
	prefix, encoded, ok := strings.Cut(signature, "=")
	if !ok || prefix != Version {
		return fmt.Errorf("unsupported signature format")
	}
	expected, err := hex.DecodeString(encoded)
	if err != nil || len(expected) != sha256.Size {
		return fmt.Errorf("invalid signature encoding")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(signingMessage(timestamp, body))
	if !hmac.Equal(expected, mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func ParseTimestamp(value string) (time.Time, error) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid webhook timestamp")
	}
	return time.Unix(seconds, 0), nil
}

func signingMessage(timestamp time.Time, body []byte) []byte {
	return []byte(strconv.FormatInt(timestamp.Unix(), 10) + "." + string(body))
}
