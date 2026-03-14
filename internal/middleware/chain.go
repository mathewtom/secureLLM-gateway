// Package middleware provides HTTP middleware for security, logging, and observability.
package middleware

import "net/http"

// Middleware wraps an http.Handler with additional behavior.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware in order. The last middleware listed wraps outermost
// and executes first on incoming requests.
//
//	Chain(handler, A, B, C) → C(B(A(handler)))
//	Request flow: C → B → A → handler → A → B → C
func Chain(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
