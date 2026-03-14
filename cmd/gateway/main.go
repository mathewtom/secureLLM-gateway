// Package main is the entry point for the SecureLLM Gateway.
//
// This application demonstrates a production-grade API gateway that sits
// in front of an LLM backend — similar to the infrastructure behind claude.ai.
// It showcases Go application security (AppSec) best practices including:
//   - OWASP Top 10 mitigations
//   - OWASP Top 10 for LLM Applications mitigations
//   - PCI DSS compliance controls
//
// Architecture overview:
//   Client → Rate Limiter → Auth/JWT → Input Sanitizer → LLM Proxy → Mock LLM
//
// Each middleware layer addresses specific security concerns and is
// independently testable.
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

	"github.com/mathewtom/secureLLM-gateway/internal/config"
	"github.com/mathewtom/secureLLM-gateway/internal/handlers"
	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
)

func main() {
	// =========================================================================
	// STRUCTURED LOGGING SETUP
	// =========================================================================
	// slog is Go's built-in structured logging package (added in Go 1.21).
	// We use JSON format because:
	//   1. It's machine-parseable — critical for log aggregation (Datadog, Splunk, ELK)
	//   2. PCI DSS Req 10.3 requires logs to include specific fields (timestamp, user, event type)
	//   3. Structured logs are easier to query and alert on in production
	//
	// In Go, slog.New() creates a new logger, and slog.NewJSONHandler() tells it
	// to output JSON. os.Stdout sends logs to standard output, which Docker/K8s
	// will capture automatically.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		// Level determines the minimum severity to log.
		// In production you'd set this to slog.LevelInfo or slog.LevelWarn.
		// For development, Debug gives us maximum visibility.
		Level: slog.LevelDebug,
	}))

	// slog.SetDefault() makes this logger the global default.
	// Any code that calls slog.Info(), slog.Error(), etc. will use this logger.
	// This is important because our middleware and handlers will all use slog
	// without needing the logger passed explicitly.
	slog.SetDefault(logger)

	// =========================================================================
	// CONFIGURATION
	// =========================================================================
	// Load configuration from environment variables.
	// SECURITY NOTE (OWASP A05 - Security Misconfiguration):
	//   We never hardcode secrets or config values. Everything comes from
	//   environment variables, which in production are injected by Kubernetes
	//   Secrets or a vault like HashiCorp Vault.
	cfg := config.Load()

	// Log the startup configuration (but NEVER log secrets — PCI Req 3.4).
	// Notice we log cfg.Port but NOT cfg.JWTSecret. This is intentional.
	slog.Info("starting secureLLM gateway",
		"port", cfg.Port,
		"environment", cfg.Environment,
	)

	// =========================================================================
	// ROUTER SETUP
	// =========================================================================
	// http.NewServeMux() creates a new HTTP request multiplexer (router).
	// A "mux" maps URL paths to handler functions. Think of it as a routing table:
	//   "/health"        → health check handler
	//   "/api/v1/chat"   → chat completion handler
	//
	// Go's standard library ServeMux is simple but production-ready.
	// We don't need a framework like Gin or Echo — keeping dependencies minimal
	// reduces supply chain attack surface (OWASP LLM05 - Supply Chain Vulnerabilities).
	mux := http.NewServeMux()

	// Register our route handlers.
	// Each handler is defined in the handlers package and is responsible for
	// one specific API endpoint.
	handlers.RegisterRoutes(mux)

	// =========================================================================
	// MIDDLEWARE CHAIN
	// =========================================================================
	// Middleware wraps our handlers with cross-cutting security concerns.
	// The order matters — requests flow through middleware top-to-bottom:
	//
	//   1. RequestID    — assigns a unique ID to every request (traceability)
	//   2. SecurityHeaders — sets HSTS, CSP, X-Frame-Options (OWASP A05)
	//   3. Logging      — logs every request for audit trail (PCI Req 10)
	//   4. Recovery     — catches panics so the server doesn't crash (availability)
	//
	// In Go, middleware is just a function that takes an http.Handler and returns
	// a new http.Handler. We chain them by wrapping one inside another.
	// The outermost middleware runs first.
	handler := middleware.Chain(
		mux,
		middleware.RequestID,        // First: assign request ID for tracing
		middleware.SecurityHeaders,  // Second: set security response headers
		middleware.Logging,          // Third: log the request (uses request ID from above)
		middleware.Recovery,         // Fourth (outermost): catch panics
	)

	// =========================================================================
	// HTTP SERVER CONFIGURATION
	// =========================================================================
	// We configure the server with explicit timeouts to prevent slowloris attacks
	// and resource exhaustion (OWASP A05 - Security Misconfiguration).
	//
	// http.Server is a struct — in Go, you create struct instances with field names.
	// The & operator creates a pointer to the struct, which is conventional for
	// server objects that will be passed around.
	server := &http.Server{
		// Addr is the address to listen on. fmt.Sprintf formats a string —
		// ":%d" means "colon followed by an integer" (e.g., ":8080").
		Addr: fmt.Sprintf(":%d", cfg.Port),

		// Handler is the root handler that processes all requests.
		// This is our middleware-wrapped mux from above.
		Handler: handler,

		// ReadTimeout limits how long the server waits for the client to send
		// the full request (headers + body). Prevents slowloris attacks where
		// an attacker sends data very slowly to tie up server resources.
		ReadTimeout: 15 * time.Second,

		// WriteTimeout limits how long the server takes to write the response.
		// For LLM streaming responses, we'll need to handle this differently
		// in the chat handler (we'll increase it per-request for SSE).
		WriteTimeout: 30 * time.Second,

		// IdleTimeout limits how long a keep-alive connection stays open
		// when idle. Lower values free up server resources faster.
		IdleTimeout: 60 * time.Second,

		// ReadHeaderTimeout specifically limits header reading time.
		// This is a more targeted defense against slowloris than ReadTimeout.
		ReadHeaderTimeout: 5 * time.Second,

		// MaxHeaderBytes limits the size of request headers.
		// Default is 1MB which is too generous — 1KB per header is plenty.
		// This prevents header-based memory exhaustion attacks.
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// =========================================================================
	// GRACEFUL SHUTDOWN
	// =========================================================================
	// Graceful shutdown is critical for production services because:
	//   1. In-flight requests should complete, not get killed mid-response
	//   2. Kubernetes sends SIGTERM before killing a pod — we need to handle it
	//   3. Database connections and other resources need to be cleaned up
	//   4. PCI DSS requires controlled shutdown procedures
	//
	// Go's goroutines and channels make graceful shutdown elegant.
	// A goroutine is a lightweight thread managed by the Go runtime.
	// A channel (chan) is how goroutines communicate safely.

	// Create a channel that receives os.Signal values.
	// make() is Go's built-in function to create channels, slices, and maps.
	// The "1" means the channel is buffered — it can hold 1 signal without blocking.
	quit := make(chan os.Signal, 1)

	// signal.Notify tells the OS to send SIGINT (Ctrl+C) and SIGTERM (kill)
	// signals to our quit channel instead of killing the process immediately.
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start the HTTP server in a goroutine (background thread).
	// The "go" keyword launches a function as a goroutine — it runs concurrently
	// with the rest of main(). This lets us listen for shutdown signals while
	// the server is running.
	go func() {
		slog.Info("server listening", "addr", server.Addr)

		// ListenAndServe starts accepting connections. It blocks until the
		// server is shut down. If it returns an error that isn't
		// ErrServerClosed (which is expected during graceful shutdown),
		// something went wrong and we should exit.
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Block here until we receive a shutdown signal.
	// The <- operator reads from a channel. This line blocks the main goroutine
	// until SIGINT or SIGTERM is received.
	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig)

	// Create a context with a 30-second deadline for the shutdown.
	// context.WithTimeout returns a context and a cancel function.
	// The cancel function releases resources — Go convention is to defer it
	// so it runs when the function exits.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// server.Shutdown() gracefully shuts down the server:
	//   1. Stops accepting new connections
	//   2. Waits for in-flight requests to complete (up to our 30s timeout)
	//   3. Returns nil on success or an error if the timeout is exceeded
	if err := server.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped gracefully")
}
