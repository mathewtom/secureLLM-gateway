package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recovery middleware catches panics in HTTP handlers and returns a 500 error
// instead of crashing the entire server.
//
// WHAT IS A PANIC?
//   In Go, a panic is an unrecoverable runtime error — similar to an unhandled
//   exception in Java or Python. Common causes:
//     - Nil pointer dereference (accessing a field on a nil pointer)
//     - Index out of bounds (accessing array[10] when it only has 5 elements)
//     - Explicit panic() calls (used for "this should never happen" situations)
//
//   When a panic occurs in a goroutine, the goroutine's stack unwinds and the
//   program crashes — UNLESS someone calls recover() in a deferred function.
//
// WHY IS THIS MIDDLEWARE CRITICAL?
//   Without recovery middleware, a single panic in any HTTP handler would crash
//   the ENTIRE server, taking down ALL connections. In production with thousands
//   of concurrent users, this is catastrophic.
//
//   This middleware ensures:
//     1. The panic is caught (recovered) — the server stays running
//     2. The error is logged with full stack trace — for debugging
//     3. The client gets a clean 500 response — not a connection reset
//     4. Other concurrent requests are unaffected
//
// SECURITY CONTEXT:
//   - OWASP A05 (Security Misconfiguration): Exposing stack traces to users
//     reveals internal implementation details. We log the trace but return
//     a generic error to the client.
//   - AVAILABILITY: In a high-volume system like claude.ai, one bad request
//     must not bring down the entire service.
//   - PCI DSS Req 6.5: Error handling must not leak sensitive information.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// defer is Go's way of saying "run this function when the surrounding
		// function returns." Deferred functions run even if a panic occurs,
		// which is why we use defer here — it's the ONLY way to catch panics.
		//
		// Multiple defers run in LIFO (last in, first out) order.
		defer func() {
			// recover() catches a panic and returns the panic value.
			// It can only be called inside a deferred function.
			// If there was no panic, recover() returns nil.
			if err := recover(); err != nil {
				// Get the stack trace. debug.Stack() returns the goroutine's
				// stack trace as a byte slice. We log it for debugging.
				stack := debug.Stack()

				// Log the panic with full context.
				// IMPORTANT: We log the full stack trace to our internal logs
				// (for debugging) but do NOT include it in the HTTP response
				// (to avoid leaking implementation details to attackers).
				slog.Error("panic recovered",
					"error", err,
					"stack", string(stack),
					"method", r.Method,
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)

				// Return a generic 500 error to the client.
				// We use http.Error() which sets Content-Type to text/plain
				// and writes the status code and message.
				//
				// SECURITY: The message is intentionally vague. Never include:
				//   - Stack traces
				//   - Internal error details
				//   - Database error messages
				//   - File paths or system information
				// These help attackers understand your system's internals.
				http.Error(w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
			}
		}()

		// Call the next handler. If it panics, the deferred function above
		// will catch it and return a clean 500 error.
		next.ServeHTTP(w, r)
	})
}
