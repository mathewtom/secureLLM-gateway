package handlers

import (
	"encoding/json"
	"net/http"
)

type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// handleHealth returns a lightweight health check for Kubernetes probes
// and load balancers. No auth required; no internal details exposed.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:  "healthy",
		Service: "secureLLM-gateway",
		Version: "0.1.0",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
