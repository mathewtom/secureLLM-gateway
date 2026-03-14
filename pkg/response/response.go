// Package response provides standardized HTTP response helpers.
//
// WHY A DEDICATED RESPONSE PACKAGE?
//   Consistent error and success responses across all handlers ensure:
//     1. Clients can parse all responses with the same logic
//     2. Error messages never accidentally leak internal details (OWASP A05)
//     3. All responses include security-relevant fields (request ID, timestamp)
//     4. PCI DSS Req 6.5: Error handling is consistent and doesn't leak info
//
// This package is in pkg/ (not internal/) because it could be useful to
// external consumers of this module. The internal/ directory in Go is special —
// packages there can only be imported by code within the same module.
// pkg/ has no such restriction.
package response

import (
	"encoding/json"
	"net/http"
	"time"
)

// ErrorResponse is the standard JSON structure for all error responses.
// Having a consistent error format makes it easier for API consumers to
// handle errors programmatically.
//
// Example:
//
//	{
//	  "error": {
//	    "code": "UNAUTHORIZED",
//	    "message": "Invalid or expired authentication token"
//	  },
//	  "request_id": "a1b2c3d4e5f6a7b8",
//	  "timestamp": "2024-01-15T10:30:00Z"
//	}
type ErrorResponse struct {
	Error     ErrorDetail `json:"error"`
	RequestID string      `json:"request_id,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// ErrorDetail contains the error code and human-readable message.
//
// WHY SEPARATE CODE AND MESSAGE?
//   - Code is machine-readable: clients can switch on it (e.g., "RATE_LIMITED")
//   - Message is human-readable: for display in UIs or debug logs
//   - This separation follows API best practices (Google, Stripe, etc.)
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JSON sends a JSON response with the given status code.
// This is a helper to reduce boilerplate in handlers.
//
// Parameters:
//   - w: the ResponseWriter to write to
//   - status: the HTTP status code (e.g., http.StatusOK, http.StatusNotFound)
//   - data: any value that can be serialized to JSON (struct, map, slice, etc.)
//
// The 'any' type (alias for interface{}) means data can be any type.
// This is Go's way of accepting "anything" — similar to Object in Java
// or Any in Kotlin. The json.Encoder handles converting it to JSON.
func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Error sends a standardized error response.
// All error responses go through this function to ensure consistency.
//
// SECURITY: The message parameter should be a user-safe message.
// NEVER pass internal error details (err.Error()) as the message —
// those go in the logs, not in the response.
func Error(w http.ResponseWriter, status int, code, message, requestID string) {
	resp := ErrorResponse{
		Error: ErrorDetail{
			Code:    code,
			Message: message,
		},
		RequestID: requestID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	JSON(w, status, resp)
}
