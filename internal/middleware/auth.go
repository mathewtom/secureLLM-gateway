package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
)

const (
	claimsKey contextKey = "claims"
	userIDKey contextKey = "userID"
)

// Auth returns middleware that validates JWT Bearer tokens from the
// Authorization header. On success, it injects the validated claims
// and user ID into the request context. On failure, returns 401.
// Error details are logged but never sent to the client.
func Auth(ts *auth.TokenService) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				slog.Debug("missing authorization header",
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Expect "Bearer <token>" per RFC 6750.
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				slog.Debug("malformed authorization header",
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ts.ValidateToken(parts[1])
			if err != nil {
				slog.Warn("token validation failed",
					"error", err,
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			ctx = context.WithValue(ctx, userIDKey, claims.Subject)

			slog.Debug("request authenticated",
				"user_id", claims.Subject,
				"role", claims.Role,
				"path", r.URL.Path,
				"request_id", GetRequestID(r.Context()),
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims retrieves validated JWT claims from the request context,
// or nil if unauthenticated.
func GetClaims(ctx context.Context) *auth.Claims {
	if claims, ok := ctx.Value(claimsKey).(*auth.Claims); ok {
		return claims
	}
	return nil
}

// GetUserID retrieves the authenticated user's ID from the request context,
// or "" if unauthenticated.
func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(userIDKey).(string); ok {
		return id
	}
	return ""
}
