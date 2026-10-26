package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modexa/webhook-delivery-platform/internal/config"
	"github.com/modexa/webhook-delivery-platform/internal/httpapi"
	"github.com/modexa/webhook-delivery-platform/internal/store"
	"github.com/modexa/webhook-delivery-platform/internal/worker"
)

func main() {
	cfg := config.Load()
	if cfg.APIKeyPepper == "" {
		slog.Error("API_KEY_PEPPER is required")
		os.Exit(1)
	}
	if cfg.BootstrapToken == "" {
		slog.Error("BOOTSTRAP_TOKEN is required")
		os.Exit(1)
	}
	if cfg.WebhookKey == "" {
		slog.Error("WEBHOOK_ENCRYPTION_KEY is required")
		os.Exit(1)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL, cfg.WebhookKey)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	workerPool := worker.New(db, cfg, logger)
	go workerPool.Run(ctx)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           httpapi.New(db, cfg, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		logger.Info("http server listening", "addr", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("http server stopped", "error", err)
			stop()
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
