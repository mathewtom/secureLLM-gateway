// Package handlers contains HTTP request handlers for the SecureLLM Gateway API.
//
// Each handler is responsible for one API endpoint. Handlers:
//   - Parse and validate the request
//   - Call business logic (in other packages)
//   - Return a properly formatted response
//
// Handlers should NOT contain business logic themselves — they are "thin"
// translation layers between HTTP and your application's internal API.
// This separation makes the code easier to test and maintain.
package handlers

import "net/http"

// RegisterRoutes maps URL paths to their handler functions.
//
// In Go 1.22+, the ServeMux supports method-based routing with the pattern
// "METHOD /path". For example, "GET /health" only matches GET requests to /health.
// Before Go 1.22, you had to check r.Method manually in each handler.
//
// SECURITY NOTE (OWASP A01 - Broken Access Control):
//   Each route will eventually have its own auth requirements:
//     - /health: No auth (needed for Kubernetes liveness probes)
//     - /api/v1/chat: Requires valid JWT with "user" or "admin" role
//     - /api/v1/admin/*: Requires valid JWT with "admin" role
//   We'll add auth middleware in a later step.
func RegisterRoutes(mux *http.ServeMux) {
	// Health check endpoint — used by:
	//   1. Kubernetes liveness probes: Is the server process alive?
	//   2. Kubernetes readiness probes: Is the server ready to accept traffic?
	//   3. Load balancers: Should traffic be routed to this instance?
	//
	// This endpoint MUST:
	//   - Return 200 OK when healthy
	//   - Be fast (no database queries, no external calls)
	//   - Not require authentication (probes don't have tokens)
	//   - Not expose sensitive information (an attacker shouldn't learn
	//     anything useful from the health endpoint)
	mux.HandleFunc("GET /health", handleHealth)

	// Chat completion endpoint — the main API for interacting with the LLM.
	// POST because we're sending data (the user's prompt) and creating a resource
	// (the LLM's response). GET would be inappropriate because:
	//   1. Prompts can be long (GET has URL length limits)
	//   2. Prompts may contain sensitive data (GET params appear in logs and browser history)
	//   3. Each request creates a new response (not idempotent)
	mux.HandleFunc("POST /api/v1/chat", handleChat)
}
