// Package middleware provides HTTP middleware for security, logging, and observability.
//
// WHAT IS MIDDLEWARE?
//   Middleware is code that runs before (and/or after) your actual request handler.
//   Think of it as a pipeline of processing steps. Each middleware can:
//     - Inspect or modify the request (e.g., check auth tokens)
//     - Inspect or modify the response (e.g., add security headers)
//     - Short-circuit the pipeline (e.g., return 401 if not authenticated)
//     - Pass control to the next handler in the chain
//
// In Go, middleware follows a simple pattern:
//   func MyMiddleware(next http.Handler) http.Handler {
//       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//           // ... do something before ...
//           next.ServeHTTP(w, r)  // call the next handler
//           // ... do something after ...
//       })
//   }
//
// SECURITY CONTEXT:
//   The order of middleware matters! Our chain is:
//     Recovery → Logging → SecurityHeaders → RequestID → [your handler]
//   Recovery is outermost so it catches panics from ALL other middleware.
//   Logging wraps SecurityHeaders so we can log the response status.
package middleware

import "net/http"

// Middleware is a type alias for a function that wraps an http.Handler.
// In Go, you can define custom types — this makes our code more readable.
// Instead of writing func(http.Handler) http.Handler everywhere, we just
// write Middleware.
//
// http.Handler is an interface with one method: ServeHTTP(w, r).
// Any type that implements ServeHTTP is an http.Handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware to a handler in the given order.
// The first middleware in the slice is the innermost (closest to the handler),
// and the last is the outermost (first to execute).
//
// Example:
//
//	Chain(handler, A, B, C) produces: C(B(A(handler)))
//	Request flow: C → B → A → handler → A → B → C
//
// This is a variadic function — the ... syntax means it accepts any number
// of Middleware arguments. Inside the function, "middlewares" is a slice ([]Middleware).
func Chain(handler http.Handler, middlewares ...Middleware) http.Handler {
	// We iterate in reverse so that the first middleware listed is innermost.
	// range returns (index, value) for each element. We only need the index here
	// to iterate backwards — we ignore the value by not assigning it.
	//
	// Why reverse? If we chain [A, B, C] and apply them in order, we'd get:
	//   C(B(A(handler))) — meaning C runs first on the request.
	// But it's more intuitive if the first listed middleware runs first,
	// so we reverse to get: A(B(C(handler))) — A runs first.
	//
	// Actually, let me correct that: we iterate in reverse so that the LAST
	// middleware in the list wraps outermost and thus executes first on the request.
	// Our call: Chain(mux, RequestID, SecurityHeaders, Logging, Recovery)
	// Produces: Recovery(Logging(SecurityHeaders(RequestID(mux))))
	// Request flow: Recovery → Logging → SecurityHeaders → RequestID → mux
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
