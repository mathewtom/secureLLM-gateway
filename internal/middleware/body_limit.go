package middleware

import (
	"log/slog"
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/pkg/response"
)

// BodyLimit returns middleware that restricts request body size to maxBytes.
// Returns 413 if the body exceeds the limit (OWASP LLM10).
func BodyLimit(maxBytes int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Early reject if Content-Length is declared and exceeds limit.
			if r.ContentLength > maxBytes {
				slog.Warn("request body too large (Content-Length)",
					"content_length", r.ContentLength,
					"max_bytes", maxBytes,
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				response.Error(w, http.StatusRequestEntityTooLarge,
					"PAYLOAD_TOO_LARGE",
					"request body exceeds maximum allowed size",
					GetRequestID(r.Context()))
				return
			}

			// Enforce limit at the read level for chunked/streaming bodies.
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

			next.ServeHTTP(w, r)
		})
	}
}
