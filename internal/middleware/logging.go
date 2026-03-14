package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
//
// WHY DO WE NEED THIS?
//   Go's http.ResponseWriter doesn't expose the status code after it's been written.
//   But we need the status code for logging — we want to log "200 OK" or "500 Error"
//   after the handler finishes. So we wrap the ResponseWriter with our own version
//   that records the status code when WriteHeader is called.
//
// This pattern is called "decorator" or "wrapper" — we add functionality without
// changing the original interface. Our wrapper still satisfies http.ResponseWriter
// because it implements all three required methods: Header(), Write(), WriteHeader().
type responseWriter struct {
	// http.ResponseWriter is embedded — this means our struct "inherits" all of
	// ResponseWriter's methods. We only need to override WriteHeader to capture
	// the status code. All other methods (Header, Write) are automatically
	// delegated to the embedded ResponseWriter.
	//
	// Embedding is Go's form of composition (not inheritance!). It's like saying
	// "a responseWriter HAS a ResponseWriter and can do everything it does."
	http.ResponseWriter

	// statusCode stores the HTTP status code for later retrieval.
	statusCode int
}

// WriteHeader captures the status code and then delegates to the original ResponseWriter.
// This method is called by handlers when they want to set the response status code
// (e.g., w.WriteHeader(http.StatusNotFound) for 404).
//
// Note: If a handler calls w.Write() without calling WriteHeader first,
// Go automatically calls WriteHeader(200). Our wrapper handles this in the
// Write() method below.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Logging middleware logs every HTTP request with structured fields.
//
// SECURITY CONTEXT:
//   - PCI DSS Req 10.1: All system components must have audit trails.
//   - PCI DSS Req 10.2: Logs must record all actions by any individual with admin access.
//   - PCI DSS Req 10.3: Log entries must include: user ID, event type, date/time,
//     success/failure, origination of event, identity/name of affected resource.
//   - OWASP A09 (Security Logging and Monitoring Failures): Insufficient logging
//     is a top-10 vulnerability. If you can't see attacks in your logs, you can't
//     detect or respond to breaches.
//
// WHAT WE LOG:
//   - HTTP method and path (what was requested)
//   - Response status code (success or failure)
//   - Duration (how long it took — useful for detecting DoS)
//   - Client IP (who made the request — required by PCI)
//   - Request ID (correlates with other log entries for the same request)
//
// WHAT WE DON'T LOG (intentionally):
//   - Request body (might contain PII, passwords, credit card numbers)
//   - Authorization headers (contain tokens/credentials)
//   - Query parameters (might contain sensitive data)
//   These omissions are required by PCI DSS Req 3.4 (don't store sensitive data)
//   and are a common source of compliance violations.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Record the start time so we can calculate request duration.
		// time.Now() returns the current time with nanosecond precision.
		start := time.Now()

		// Wrap the ResponseWriter so we can capture the status code.
		// &responseWriter{...} creates a pointer to a new responseWriter struct.
		// We initialize statusCode to 200 because if the handler never calls
		// WriteHeader, Go defaults to 200 (OK).
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // default to 200
		}

		// Call the next handler in the chain.
		// After this returns, the response has been written and we can log it.
		next.ServeHTTP(wrapped, r)

		// Calculate the request duration.
		// time.Since(start) is equivalent to time.Now().Sub(start).
		duration := time.Since(start)

		// Log the request with structured fields.
		// slog.Info creates an INFO-level log entry. The first argument is the message,
		// followed by key-value pairs that become structured fields in the JSON output.
		//
		// Example JSON output:
		// {
		//   "time": "2024-01-15T10:30:00Z",
		//   "level": "INFO",
		//   "msg": "http request",
		//   "method": "POST",
		//   "path": "/api/v1/chat",
		//   "status": 200,
		//   "duration_ms": 150.5,
		//   "client_ip": "192.168.1.1:50234",
		//   "request_id": "a1b2c3d4e5f6a7b8"
		// }
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapped.statusCode,
			"duration_ms", float64(duration.Nanoseconds())/1e6,
			"client_ip", r.RemoteAddr,
			"request_id", GetRequestID(r.Context()),
		)
	})
}
