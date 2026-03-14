package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/mathewtom/secureLLM-gateway/internal/middleware"
)

type chatRequest struct {
	Message string `json:"message"`
	Model   string `json:"model"`
}

type chatResponse struct {
	ID        string `json:"id"`
	Response  string `json:"response"`
	Model     string `json:"model"`
	CreatedAt string `json:"created_at"`
}

// handleChat processes chat completion requests. Currently returns a mock
// response; will be extended with prompt injection detection, output
// sanitization, rate limiting, and real LLM backend integration.
func handleChat(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Message == "" {
		http.Error(w, `{"error": "message is required"}`, http.StatusBadRequest)
		return
	}

	if req.Model == "" {
		req.Model = "mock-llm-v1"
	}

	resp := chatResponse{
		ID:        middleware.GetRequestID(r.Context()),
		Response:  "This is a mock LLM response. The real LLM integration is coming soon!",
		Model:     req.Model,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
