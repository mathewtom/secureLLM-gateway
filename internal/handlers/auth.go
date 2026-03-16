package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/mathewtom/secureLLM-gateway/internal/auth"
)

type tokenRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

type demoUser struct {
	Password string
	Email    string
	Role     auth.Role
}

// demoUsers provides hardcoded credentials for development and testing.
// In production, replace with a user database and bcrypt/argon2 hashing.
var demoUsers = map[string]demoUser{
	"admin": {
		Password: "admin123",
		Email:    "admin@securellm.dev",
		Role:     auth.RoleAdmin,
	},
	"user1": {
		Password: "user123",
		Email:    "user1@securellm.dev",
		Role:     auth.RoleUser,
	},
	"viewer": {
		Password: "view123",
		Email:    "viewer@securellm.dev",
		Role:     auth.RoleReadOnly,
	},
}

// NewAuthHandler returns a handler that authenticates credentials and issues
// a signed JWT. Uses a single error message for invalid user/password to
// prevent username enumeration (OWASP A07).
func NewAuthHandler(ts *auth.TokenService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			http.Error(w, `{"error": "username and password are required"}`, http.StatusBadRequest)
			return
		}

		user, exists := demoUsers[req.Username]
		if !exists || user.Password != req.Password {
			http.Error(w, `{"error": "invalid credentials"}`, http.StatusUnauthorized)
			return
		}

		token, err := ts.GenerateToken(req.Username, user.Email, user.Role)
		if err != nil {
			http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			return
		}

		resp := tokenResponse{
			Token:     token,
			TokenType: "Bearer",
			ExpiresIn: 3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
