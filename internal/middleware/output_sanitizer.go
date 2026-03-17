package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/mathewtom/secureLLM-gateway/internal/sanitizer"
)

// bufferedResponseWriter captures the response body in a buffer,
// allowing inspection and modification before sending to the client.
type bufferedResponseWriter struct {
	http.ResponseWriter               // Embedded — delegates Header() etc.
	buf                 bytes.Buffer  // Captured response body.
	statusCode          int           // Status code set by the handler.
	wroteHeader         bool          // Whether WriteHeader was called.
}

// WriteHeader captures the status code without sending it.
func (bw *bufferedResponseWriter) WriteHeader(code int) {
	if !bw.wroteHeader {
		bw.statusCode = code
		bw.wroteHeader = true
	}
}

// Write captures bytes into the buffer instead of sending to the client.
func (bw *bufferedResponseWriter) Write(b []byte) (int, error) {
	if !bw.wroteHeader {
		bw.statusCode = http.StatusOK
		bw.wroteHeader = true
	}
	return bw.buf.Write(b)
}

// OutputSanitizer returns middleware that sanitizes LLM response bodies
// through PII redaction, HTML encoding, and content filtering (OWASP LLM02/LLM05).
func OutputSanitizer(os *sanitizer.OutputSanitizer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Wrap the ResponseWriter to capture the response body.
			bw := &bufferedResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Run the handler — writes go to our buffer.
			next.ServeHTTP(bw, r)

			body := bw.buf.Bytes()

			// Only sanitize JSON responses with a "response" field (chat
			// completions). Pass through errors, health checks, etc. unchanged.
			if !isJSONResponse(bw) || len(body) == 0 {
				writeThrough(w, bw.statusCode, body)
				return
			}

			// Parse the response to find the LLM output field.
			var respMap map[string]any
			if err := json.Unmarshal(body, &respMap); err != nil {
				writeThrough(w, bw.statusCode, body)
				return
			}

			responseText, ok := respMap["response"].(string)
			if !ok || responseText == "" {
				writeThrough(w, bw.statusCode, body)
				return
			}

			// Run the three-stage sanitization pipeline.
			result := os.Sanitize(responseText)

			// Log redaction and flagging activity for audit trail.
			reqID := GetRequestID(r.Context())
			userID := GetUserID(r.Context())

			if result.PIIRedacted > 0 {
				slog.Warn("PII redacted from LLM response",
					"user_id", userID,
					"pii_count", result.PIIRedacted,
					"path", r.URL.Path,
					"request_id", reqID,
				)
			}

			if len(result.ContentFlags) > 0 {
				flagDescriptions := make([]string, 0, len(result.ContentFlags))
				for _, f := range result.ContentFlags {
					flagDescriptions = append(flagDescriptions, f.Description)
				}
				slog.Warn("harmful content flagged in LLM response",
					"user_id", userID,
					"flags", flagDescriptions,
					"path", r.URL.Path,
					"request_id", reqID,
				)
			}

			// Replace the response text with sanitized version.
			respMap["response"] = result.Output

			sanitizedBody, err := json.Marshal(respMap)
			if err != nil {
				slog.Error("failed to marshal sanitized response",
					"error", err,
					"request_id", reqID,
				)
				writeThrough(w, bw.statusCode, body)
				return
			}

			// Write the sanitized response to the client.
			w.Header().Set("Content-Length", strconv.Itoa(len(sanitizedBody)))
			w.WriteHeader(bw.statusCode)
			w.Write(sanitizedBody)
		})
	}
}

// isJSONResponse checks if the buffered response has a JSON content type.
func isJSONResponse(bw *bufferedResponseWriter) bool {
	ct := bw.Header().Get("Content-Type")
	return len(ct) >= 16 && ct[:16] == "application/json"
}

// writeThrough sends the original buffered response unchanged.
func writeThrough(w http.ResponseWriter, statusCode int, body []byte) {
	w.WriteHeader(statusCode)
	w.Write(body)
}
