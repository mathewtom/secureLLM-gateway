// Package handlers contains HTTP request handlers for the SecureLLM Gateway API.
package handlers

import (
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
	"github.com/mathewtom/secureLLM-gateway/internal/ratelimit"
)

// RegisterRoutes maps URL patterns to handlers with per-route auth,
// rate limiting, and RBAC.
func RegisterRoutes(mux *http.ServeMux, ts *auth.TokenService, limiter *ratelimit.Limiter) {
	// Public routes.
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /api/v1/auth/token", NewAuthHandler(ts))

	// Protected routes — Auth → RateLimit → RequireRole → handler.
	mux.Handle("POST /api/v1/chat", wrapHandler(
		http.HandlerFunc(handleChat),
		ts,
		limiter,
		auth.RoleUser, auth.RoleAdmin,
	))
}

// wrapHandler applies Auth → RateLimit → RequireRole middleware to a handler.
func wrapHandler(handler http.Handler, ts *auth.TokenService, limiter *ratelimit.Limiter, roles ...auth.Role) http.Handler {
	handler = middleware.RequireRole(roles...)(handler)
	handler = middleware.RateLimit(limiter)(handler)
	handler = middleware.Auth(ts)(handler)
	return handler
}
