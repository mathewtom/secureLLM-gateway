// Package handlers contains HTTP request handlers for the SecureLLM Gateway API.
package handlers

import "net/http"

// RegisterRoutes maps URL patterns to handler functions.
// Auth middleware will be layered on per-route in a later iteration.
func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("POST /api/v1/chat", handleChat)
}
