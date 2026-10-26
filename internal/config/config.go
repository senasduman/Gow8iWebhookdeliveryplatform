package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr           string
	DatabaseURL        string
	WorkerCount        int
	PollInterval       time.Duration
	DeliveryTimeout    time.Duration
	MaxAttempts        int
	APIKeyPepper       string
	BootstrapToken     string
	WebhookKey         string
	LegacySecretHeader bool
}

func Load() Config {
	return Config{
		HTTPAddr:           env("HTTP_ADDR", ":8080"),
		DatabaseURL:        env("DATABASE_URL", "postgres://webhook:webhook@localhost:5432/webhook?sslmode=disable"),
		WorkerCount:        envInt("WORKER_COUNT", 4),
		PollInterval:       envDuration("POLL_INTERVAL", time.Second),
		DeliveryTimeout:    envDuration("DELIVERY_TIMEOUT", 10*time.Second),
		MaxAttempts:        envInt("MAX_ATTEMPTS", 8),
		APIKeyPepper:       os.Getenv("API_KEY_PEPPER"),
		BootstrapToken:     os.Getenv("BOOTSTRAP_TOKEN"),
		WebhookKey:         os.Getenv("WEBHOOK_ENCRYPTION_KEY"),
		LegacySecretHeader: envBool("WEBHOOK_LEGACY_SECRET_HEADER", false),
	}
}
func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "TRUE"
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(env(key, ""))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}
func envDuration(key string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(env(key, ""))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
