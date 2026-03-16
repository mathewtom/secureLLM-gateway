// Package handlers contains HTTP request handlers for the SecureLLM Gateway API.
package handlers

import (
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
)

// RegisterRoutes maps URL patterns to handlers with per-route auth and RBAC.
// Public routes (health, token) have no auth; protected routes require
// a valid JWT and an allowed role.
func RegisterRoutes(mux *http.ServeMux, ts *auth.TokenService) {
	// Public routes.
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /api/v1/auth/token", NewAuthHandler(ts))

	// Protected routes — Auth validates the JWT, RequireRole checks authorization.
	mux.Handle("POST /api/v1/chat", wrapHandler(
		http.HandlerFunc(handleChat),
		ts,
		auth.RoleUser, auth.RoleAdmin,
	))
}

// wrapHandler applies Auth → RequireRole middleware to a single handler.
func wrapHandler(handler http.Handler, ts *auth.TokenService, roles ...auth.Role) http.Handler {
	handler = middleware.RequireRole(roles...)(handler)
	handler = middleware.Auth(ts)(handler)
	return handler
}
