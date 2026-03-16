// Package main is the entry point for the SecureLLM Gateway.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
	"github.com/mathewtom/secureLLM-gateway/internal/config"
	"github.com/mathewtom/secureLLM-gateway/internal/handlers"
	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
	"github.com/mathewtom/secureLLM-gateway/internal/ratelimit"
)

func main() {
	// Structured JSON logging for log aggregation and PCI DSS Req 10.3 compliance.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Load configuration from environment variables (never hardcoded).
	cfg := config.Load()

	slog.Info("starting secureLLM gateway",
		"port", cfg.Port,
		"environment", cfg.Environment,
	)

	// Initialize JWT token service for authentication.
	tokenService := auth.NewTokenService(cfg.JWTSecret, cfg.JWTExpiration, "securellm-gateway")

	// Per-user rate limiter with role-based token bucket rates.
	limiter := ratelimit.NewLimiter(
		ratelimit.RoleRates{
			"admin":    {RequestsPerSecond: float64(cfg.RateLimitAdmin), Burst: cfg.RateLimitBurst},
			"user":     {RequestsPerSecond: float64(cfg.RateLimitUser), Burst: cfg.RateLimitBurst},
			"readonly": {RequestsPerSecond: float64(cfg.RateLimitReadonly), Burst: cfg.RateLimitBurst},
		},
		ratelimit.Rate{RequestsPerSecond: float64(cfg.RateLimitUser), Burst: cfg.RateLimitBurst},
		5*time.Minute,  // Cleanup interval.
		10*time.Minute, // Bucket TTL.
	)
	defer limiter.Stop()

	// Router setup — standard library ServeMux to minimize dependency surface.
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux, tokenService, limiter)

	// Middleware chain applied outermost-first on incoming requests:
	// Recovery → Logging → SecurityHeaders → RequestID → handler
	handler := middleware.Chain(
		mux,
		middleware.RequestID,
		middleware.SecurityHeaders,
		middleware.Logging,
		middleware.Recovery,
	)

	// Explicit timeouts to mitigate slowloris and resource exhaustion.
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Graceful shutdown: catch SIGINT/SIGTERM, drain in-flight requests.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("server listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
