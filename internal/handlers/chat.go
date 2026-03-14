// This file contains the chat completion handler — the main API endpoint
// for interacting with the LLM backend.
//
// For now, this is a stub that returns a mock response. In later steps, we'll add:
//   - Request validation and size limits
//   - Prompt injection detection (OWASP LLM01)
//   - Output sanitization (OWASP LLM02)
//   - Streaming SSE responses
//   - Rate limiting integration
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
)

// chatRequest represents the JSON body of a chat completion request.
// This is what the client sends to us.
//
// In a real LLM gateway (like the OpenAI or Anthropic API), the request
// would include the model name, temperature, max tokens, etc. We're keeping
// it simple for now and will expand later.
type chatRequest struct {
	// Message is the user's prompt text.
	// The json tag maps the JSON key "message" to this Go field.
	Message string `json:"message"`

	// Model specifies which LLM model to use.
	// In production, different models have different costs, capabilities,
	// and rate limits. We'll use this for RBAC later — some users might
	// only have access to cheaper models.
	Model string `json:"model"`
}

// chatResponse represents the JSON body we send back to the client.
type chatResponse struct {
	// ID is a unique identifier for this completion.
	// Useful for auditing, debugging, and idempotency.
	ID string `json:"id"`

	// Response is the LLM's generated text.
	Response string `json:"response"`

	// Model echoes back which model was used.
	Model string `json:"model"`

	// CreatedAt is the timestamp of when the response was generated.
	// Using ISO 8601 format (Go's time.RFC3339) for consistency.
	CreatedAt string `json:"created_at"`
}

// handleChat processes chat completion requests.
//
// Request flow (current):
//  1. Parse JSON body
//  2. Basic validation
//  3. Return mock response
//
// Request flow (planned):
//  1. Parse JSON body
//  2. Validate input size and structure
//  3. Check rate limits (OWASP LLM04)
//  4. Scan for prompt injection (OWASP LLM01)
//  5. Forward to LLM backend
//  6. Sanitize LLM output (OWASP LLM02)
//  7. Log the interaction (PCI Req 10)
//  8. Return response
func handleChat(w http.ResponseWriter, r *http.Request) {
	// =========================================================================
	// PARSE REQUEST BODY
	// =========================================================================
	// json.NewDecoder reads JSON from the request body (r.Body) and parses it
	// into our chatRequest struct. The & operator passes a pointer so Decode
	// can modify the struct directly.
	//
	// SECURITY NOTE: We should limit the request body size to prevent
	// memory exhaustion attacks. We'll add this in the next iteration
	// using http.MaxBytesReader.
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// If the JSON is malformed, return a 400 Bad Request.
		// SECURITY: We return a generic message, not the parse error details.
		// Parse errors can reveal expected field names and types to attackers.
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	// =========================================================================
	// BASIC VALIDATION
	// =========================================================================
	// Always validate input at the boundary (where external data enters your system).
	// This is the first line of defense against:
	//   - OWASP A03 (Injection): Reject obviously malformed input early
	//   - OWASP LLM01 (Prompt Injection): We'll add deeper checks later
	if req.Message == "" {
		http.Error(w, `{"error": "message is required"}`, http.StatusBadRequest)
		return
	}

	// Default model if not specified.
	// In Go, the zero value for string is "" (empty string).
	// This is different from many languages where it would be null/nil.
	if req.Model == "" {
		req.Model = "mock-llm-v1"
	}

	// =========================================================================
	// MOCK LLM RESPONSE
	// =========================================================================
	// In later steps, this is where we'd call the actual LLM backend.
	// For now, we return a canned response to verify our pipeline works end-to-end.
	//
	// GetRequestID retrieves the unique request ID that was assigned by our
	// RequestID middleware. We use it as the completion ID for traceability.
	resp := chatResponse{
		ID:        middleware.GetRequestID(r.Context()),
		Response:  "This is a mock LLM response. The real LLM integration is coming soon!",
		Model:     req.Model,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// =========================================================================
	// SEND RESPONSE
	// =========================================================================
	// Set Content-Type before writing the body.
	// w.Header().Set() modifies response headers. Headers MUST be set before
	// calling w.Write() or w.WriteHeader(), otherwise they're silently ignored.
	w.Header().Set("Content-Type", "application/json")

	// Encode the response struct as JSON and write it to the response body.
	// json.NewEncoder(w).Encode() is a one-liner that:
	//   1. Creates a JSON encoder targeting the ResponseWriter
	//   2. Serializes the struct to JSON
	//   3. Writes the JSON bytes to the response
	//   4. Adds a trailing newline (Encode adds '\n')
	json.NewEncoder(w).Encode(resp)
}
