package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/sanitizer"
	"github.com/mathewtom/secureLLM-gateway/pkg/response"
)

// chatBody extracts the message field without importing handler types.
type chatBody struct {
	Message string `json:"message"`
}

// PromptGuard returns middleware that scans chat request bodies for prompt
// injection attacks (OWASP LLM01). Must be applied after Auth middleware.
// Returns 400 with a generic error on detection — no details are leaked
// to avoid revealing detection logic.
func PromptGuard(guard *sanitizer.PromptGuard) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Read body for scanning, then rewind for downstream handler.
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				slog.Error("failed to read request body for prompt scanning",
					"error", err,
					"request_id", GetRequestID(r.Context()),
				)
				response.Error(w, http.StatusBadRequest, "BAD_REQUEST",
					"unable to read request body", GetRequestID(r.Context()))
				return
			}

			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			var body chatBody
			if err := json.Unmarshal(bodyBytes, &body); err != nil {
				// Malformed JSON — let the handler return the proper error.
				next.ServeHTTP(w, r)
				return
			}

			if body.Message == "" {
				next.ServeHTTP(w, r)
				return
			}

			result := guard.Scan(body.Message)

			if result.Blocked {
				matchDescriptions := make([]string, 0, len(result.Matches))
				for _, m := range result.Matches {
					matchDescriptions = append(matchDescriptions, m.Description)
				}

				slog.Warn("prompt injection detected — request blocked",
					"user_id", GetUserID(r.Context()),
					"score", result.TotalScore,
					"threshold", result.Threshold,
					"matches", matchDescriptions,
					"path", r.URL.Path,
					"request_id", GetRequestID(r.Context()),
				)

				// Generic error — never reveal detection logic to the client.
				response.Error(w, http.StatusBadRequest, "INVALID_INPUT",
					"request contains disallowed content", GetRequestID(r.Context()))
				return
			}

			slog.Debug("prompt scan passed",
				"user_id", GetUserID(r.Context()),
				"score", result.TotalScore,
				"path", r.URL.Path,
				"request_id", GetRequestID(r.Context()),
			)

			next.ServeHTTP(w, r)
		})
	}
}
