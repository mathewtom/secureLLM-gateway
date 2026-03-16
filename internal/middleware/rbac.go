package middleware

import (
	"log/slog"
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
)

// RequireRole returns middleware that restricts access to users with one of
// the specified roles. Must be applied after Auth middleware in the chain.
// Returns 403 if the user's role is not in the allowed set.
// Implements OWASP A01 mitigation and PCI DSS Req 7 (least privilege).
func RequireRole(allowedRoles ...auth.Role) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail closed: no claims means Auth middleware didn't run.
			claims := GetClaims(r.Context())
			if claims == nil {
				slog.Error("RBAC check with no auth claims",
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
				return
			}

			allowed := false
			for _, role := range allowedRoles {
				if claims.Role == role {
					allowed = true
					break
				}
			}

			if !allowed {
				slog.Warn("access denied: insufficient role",
					"user_id", claims.Subject,
					"user_role", claims.Role,
					"required_roles", allowedRoles,
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)
				http.Error(w, `{"error": "forbidden"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
