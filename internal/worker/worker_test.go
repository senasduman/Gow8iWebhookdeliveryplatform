package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modexa/webhook-delivery-platform/internal/config"
	"github.com/modexa/webhook-delivery-platform/internal/signing"
)

func TestDeliveryRequestUsesHMACAndDoesNotExposeLegacySecretByDefault(t *testing.T) {
	payload := []byte(`{"id":1}`)
	w := New(nil, config.Config{}, nil)
	req, err := w.newDeliveryRequest(context.Background(), uuid.New(), uuid.New(), "order.created", payload, "https://example.com/hook", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Webhook-Secret") != "" {
		t.Fatal("legacy secret header enabled by default")
	}
	timestamp, err := signing.ParseTimestamp(req.Header.Get(signing.TimestampHeader))
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Verify("secret", req.Header.Get(signing.SignatureHeader), timestamp, payload, timestamp, 5*time.Minute); err != nil {
		t.Fatalf("request signature invalid: %v", err)
	}
}

func TestDeliveryRequestCanOptIntoLegacyHeaderDuringTransition(t *testing.T) {
	w := New(nil, config.Config{LegacySecretHeader: true}, nil)
	req, err := w.newDeliveryRequest(context.Background(), uuid.New(), uuid.New(), "order.created", []byte("body"), "https://example.com/hook", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("X-Webhook-Secret") != "secret" {
		t.Fatal("legacy compatibility header was not enabled")
	}
}

func TestRetriesReuseDeliveryIDAndSignEachExactBody(t *testing.T) {
	payload := []byte(`{"attempt":1}`)
	deliveryID := uuid.New()
	eventID := uuid.New()
	w := New(nil, config.Config{}, nil)
	first, err := w.newDeliveryRequest(context.Background(), deliveryID, eventID, "order.created", payload, "https://example.com/hook", "secret")
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.newDeliveryRequest(context.Background(), deliveryID, eventID, "order.created", payload, "https://example.com/hook", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if first.Header.Get("X-Delivery-ID") != second.Header.Get("X-Delivery-ID") {
		t.Fatal("retry changed logical delivery ID")
	}
	for _, req := range []*http.Request{first, second} {
		timestamp, err := signing.ParseTimestamp(req.Header.Get(signing.TimestampHeader))
		if err != nil {
			t.Fatal(err)
		}
		if err := signing.Verify("secret", req.Header.Get(signing.SignatureHeader), timestamp, payload, timestamp, 5*time.Minute); err != nil {
			t.Fatalf("retry signature invalid: %v", err)
		}
	}
}

func TestSendDeliveryReturnsReceiverFailuresAndTimeouts(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "temporary", http.StatusInternalServerError)
	}))
	defer failing.Close()
	w := New(nil, config.Config{DeliveryTimeout: 50 * time.Millisecond}, nil)
	status, body, err := w.sendDelivery(context.Background(), uuid.New(), uuid.New(), "order.created", []byte(`{}`), failing.URL, "secret")
	if err != nil || status != http.StatusInternalServerError {
		t.Fatalf("500 response status=%d err=%v", status, err)
	}
	if body == "" {
		t.Fatal("receiver response body was discarded")
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer slow.Close()
	_, _, err = w.sendDelivery(context.Background(), uuid.New(), uuid.New(), "order.created", []byte(`{}`), slow.URL, "secret")
	if err == nil {
		t.Fatal("receiver timeout was not reported")
	}
}
