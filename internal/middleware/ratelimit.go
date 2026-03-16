package middleware

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/ratelimit"
	"github.com/mathewtom/secureLLM-gateway/pkg/response"
)

// RateLimit enforces per-user rate limits using a token bucket algorithm.
// Must be applied after Auth middleware. Returns 429 with Retry-After header
// when the user's bucket is exhausted (RFC 6585, OWASP API4:2023).
func RateLimit(limiter *ratelimit.Limiter) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail closed if Auth middleware did not populate identity.
			userID := GetUserID(r.Context())
			if userID == "" {
				slog.Error("rate limit middleware invoked without user identity",
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED",
					"authentication required", GetRequestID(r.Context()))
				return
			}

			role := ""
			if claims := GetClaims(r.Context()); claims != nil {
				role = string(claims.Role)
			}

			allowed, retryAfter := limiter.Allow(userID, role)
			if !allowed {
				slog.Warn("rate limit exceeded",
					"user_id", userID,
					"role", role,
					"retry_after_seconds", int(retryAfter.Seconds()),
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)

				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())))
				response.Error(w, http.StatusTooManyRequests, "RATE_LIMITED",
					"rate limit exceeded, try again later", GetRequestID(r.Context()))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
