// Package handlers contains HTTP request handlers for the SecureLLM Gateway API.
package handlers

import (
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
	"github.com/mathewtom/secureLLM-gateway/internal/ratelimit"
	"github.com/mathewtom/secureLLM-gateway/internal/sanitizer"
)

// RegisterRoutes maps URL patterns to handlers with per-route auth,
// rate limiting, prompt injection detection, and RBAC.
func RegisterRoutes(mux *http.ServeMux, ts *auth.TokenService, limiter *ratelimit.Limiter, guard *sanitizer.PromptGuard) {
	// Public routes.
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /api/v1/auth/token", NewAuthHandler(ts))

	// Protected routes — Auth → RateLimit → PromptGuard → RequireRole → handler.
	mux.Handle("POST /api/v1/chat", wrapHandler(
		http.HandlerFunc(handleChat),
		ts,
		limiter,
		guard,
		auth.RoleUser, auth.RoleAdmin,
	))
}

// wrapHandler applies Auth → RateLimit → PromptGuard → RequireRole middleware.
func wrapHandler(handler http.Handler, ts *auth.TokenService, limiter *ratelimit.Limiter, guard *sanitizer.PromptGuard, roles ...auth.Role) http.Handler {
	handler = middleware.RequireRole(roles...)(handler)
	handler = middleware.PromptGuard(guard)(handler)
	handler = middleware.RateLimit(limiter)(handler)
	handler = middleware.Auth(ts)(handler)
	return handler
}
