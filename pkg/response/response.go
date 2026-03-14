// Package response provides standardized HTTP response helpers.
package response

import (
	"encoding/json"
	"net/http"
	"time"
)

// ErrorResponse is the standard JSON envelope for all error responses.
type ErrorResponse struct {
	Error     ErrorDetail `json:"error"`
	RequestID string      `json:"request_id,omitempty"`
	Timestamp string      `json:"timestamp"`
}

// ErrorDetail carries a machine-readable code and a human-readable message.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JSON writes a JSON response with the given status code.
func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Error sends a standardized error response. The message should be user-safe;
// internal error details belong in logs, not responses.
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
