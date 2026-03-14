package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// contextKey is a custom type for context keys to avoid collisions.
//
// WHY A CUSTOM TYPE?
//   Go's context.WithValue uses interface{} keys. If two packages both use
//   the string "requestID" as a key, they'd collide. By defining our own
//   unexported type, only this package can create keys of this type,
//   guaranteeing uniqueness. This is a Go best practice.
//
// WHAT IS context.Context?
//   Context carries request-scoped data (like request IDs, auth info) and
//   cancellation signals across API boundaries and goroutines. Every HTTP
//   request in Go has a context accessible via r.Context(). It's the Go way
//   to pass "ambient" data without modifying function signatures.
type contextKey string

// requestIDKey is the context key for storing/retrieving the request ID.
// It's unexported (lowercase) so only this package can access it directly.
// External packages use GetRequestID() to retrieve it.
const requestIDKey contextKey = "requestID"

// RequestID is middleware that assigns a unique identifier to every request.
//
// WHY REQUEST IDS?
//   - Distributed tracing: In a microservices architecture, a single user action
//     may hit 5+ services. The request ID ties all those logs together.
//   - PCI DSS Req 10.3.1: Audit logs must include a unique identifier per event.
//   - Debugging: When a user reports "I got an error," you can search logs by
//     the request ID from their error response to find exactly what happened.
//   - OWASP A09 (Security Logging and Monitoring Failures): Correlating events
//     across services requires a shared identifier.
//
// The request ID is:
//   1. Generated server-side (never trust client-provided IDs)
//   2. Added to the request context (so handlers can access it)
//   3. Added to the response header (so the client can reference it)
func RequestID(next http.Handler) http.Handler {
	// http.HandlerFunc is an adapter that lets us use a regular function
	// as an http.Handler. It implements the ServeHTTP method by calling itself.
	// This is a common Go pattern called "adapter types."
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Generate a cryptographically random request ID.
		// We use crypto/rand (not math/rand) because:
		//   - math/rand is predictable (pseudorandom) — an attacker could predict IDs
		//   - crypto/rand uses the OS's secure random source (/dev/urandom on Linux)
		//   - For request IDs, predictability isn't catastrophic, but using crypto/rand
		//     is a good habit and there's no meaningful performance difference.
		id := generateRequestID()

		// Add the request ID to the response headers.
		// X-Request-ID is a widely-used convention (supported by nginx, AWS ALB, etc.).
		// The client receives this in the response and can quote it in support tickets.
		w.Header().Set("X-Request-ID", id)

		// Store the request ID in the request's context.
		// context.WithValue creates a NEW context that contains the key-value pair.
		// Contexts are immutable — WithValue doesn't modify the original, it wraps it.
		// r.WithContext creates a new request with the updated context.
		ctx := context.WithValue(r.Context(), requestIDKey, id)

		// Pass the request (with the new context) to the next handler.
		// next.ServeHTTP is how you "call" the next handler in the chain.
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID extracts the request ID from a context.
// This is the public API for other packages to retrieve the request ID.
//
// It returns the ID string, or "" if no request ID is set (shouldn't happen
// if the middleware is properly configured, but defensive coding is good practice).
func GetRequestID(ctx context.Context) string {
	// Type assertion: ctx.Value returns interface{}, so we assert it's a string.
	// The "ok" pattern (comma-ok idiom) safely handles the case where the value
	// is nil or not a string — if ok is false, id will be the zero value ("").
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// generateRequestID creates a 16-character hex string (8 random bytes).
// This gives us 2^64 possible values — collision probability is negligible
// even at millions of requests per second.
func generateRequestID() string {
	// make() creates a byte slice with 8 elements, all initialized to 0.
	// A byte slice ([]byte) is Go's way of working with raw binary data.
	b := make([]byte, 8)

	// rand.Read fills the slice with cryptographically secure random bytes.
	// It returns (n int, err error). We ignore both because:
	//   - On modern systems, crypto/rand.Read never fails
	//   - If it did fail, we'd get a zero ID, which is acceptable for a request ID
	//     (the request would still be processed, just harder to trace)
	_, _ = rand.Read(b)

	// hex.EncodeToString converts bytes to a hex string.
	// 8 bytes → 16 hex characters (e.g., "a1b2c3d4e5f6a7b8")
	return hex.EncodeToString(b)
}
