package handlers

import (
	"encoding/json"
	"net/http"
)

// healthResponse defines the JSON structure returned by the health endpoint.
//
// In Go, struct field tags (the `json:"..."` part) control how the struct
// is serialized to JSON. Without tags, the JSON keys would match the Go
// field names exactly (e.g., "Status" instead of "status").
//
// Convention: JSON keys are lowercase/snake_case, Go fields are PascalCase.
type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// handleHealth returns a simple health check response.
//
// Kubernetes sends HTTP GET requests to this endpoint to determine if the pod
// is alive (liveness) and ready to serve traffic (readiness).
//
// Example response:
//
//	{
//	  "status": "healthy",
//	  "service": "secureLLM-gateway",
//	  "version": "0.1.0"
//	}
//
// SECURITY NOTES:
//   - No auth required (Kubernetes probes don't have tokens)
//   - Does NOT expose internal details (uptime, memory usage, connected DBs)
//     because an attacker could use those to profile the system
//   - Version is intentionally vague for now — in production, consider whether
//     exposing the exact version helps attackers find known vulnerabilities
func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Create the response struct.
	// In Go, you create struct instances with either named fields (like here)
	// or positional values. Named fields are clearer and safer — if someone
	// adds a field to the struct later, positional initialization would break.
	resp := healthResponse{
		Status:  "healthy",
		Service: "secureLLM-gateway",
		Version: "0.1.0",
	}

	// Set the Content-Type header BEFORE calling WriteHeader or Write.
	// Once you call Write(), Go automatically sends a 200 status and headers.
	// Setting headers after Write() has no effect.
	//
	// application/json tells the client to parse the response body as JSON.
	// Without this, the client might try to interpret JSON as plain text.
	w.Header().Set("Content-Type", "application/json")

	// json.NewEncoder creates a JSON encoder that writes directly to w (the ResponseWriter).
	// Encode() serializes the struct to JSON and writes it.
	//
	// Alternative: json.Marshal(resp) returns a []byte, which you'd then w.Write().
	// NewEncoder is slightly more efficient because it writes directly without
	// creating an intermediate byte slice.
	//
	// If encoding fails (shouldn't happen with simple structs), the error is
	// silently ignored here. In production handlers with complex types,
	// you'd want to handle this error.
	json.NewEncoder(w).Encode(resp)
}
