// Package config handles application configuration loaded from environment variables.
//
// SECURITY CONTEXT:
//   - OWASP A05 (Security Misconfiguration): All config comes from env vars, never hardcoded.
//   - PCI DSS Req 2: Systems must not use vendor-supplied defaults.
//   - PCI DSS Req 3.4: Sensitive data (like JWTSecret) must never be logged or exposed.
//
// WHY ENVIRONMENT VARIABLES?
//   In a Kubernetes deployment, config is injected via:
//     - ConfigMaps (for non-sensitive config like port numbers)
//     - Secrets (for sensitive config like JWT keys, encrypted at rest)
//   Environment variables are the standard way to pass both into containers.
//   This follows the "12-Factor App" methodology (https://12factor.net/config).
package config

import (
	"os"
	"strconv"
)

// Config holds all application configuration.
// In Go, a struct is like a class without methods — it groups related data together.
// Each field has a name, a type, and we're using sensible defaults for dev.
type Config struct {
	// Port is the TCP port the HTTP server listens on.
	// Standard practice: use 8080 for non-privileged containers (not 80 or 443).
	// Ports below 1024 require root privileges, which violates security best practices.
	Port int

	// Environment identifies the runtime environment (development, staging, production).
	// We use this to adjust behavior — for example:
	//   - development: verbose logging, relaxed CORS
	//   - production: minimal logging, strict CORS, TLS required
	Environment string

	// JWTSecret is the symmetric key used to sign and verify JWT tokens.
	// SECURITY WARNING: In production, use asymmetric keys (RS256) instead of
	// symmetric (HS256). Symmetric keys mean every service that verifies tokens
	// also has the ability to create them — a compromised service can forge tokens.
	// We use symmetric here for simplicity during development.
	//
	// PCI DSS Req 3.4: This value must NEVER appear in logs.
	JWTSecret string

	// RateLimitRPS is the maximum requests per second allowed per user/IP.
	// This mitigates:
	//   - OWASP LLM04 (Model Denial of Service): prevents users from overwhelming the LLM
	//   - General DDoS: limits resource consumption per client
	//   - Cost control: LLM API calls are expensive ($$$)
	RateLimitRPS int

	// AllowedOrigins specifies which domains can make cross-origin requests (CORS).
	// OWASP A05 (Security Misconfiguration): Overly permissive CORS is a common mistake.
	// "*" allows any origin — only acceptable in development.
	AllowedOrigins string
}

// Load reads configuration from environment variables and returns a Config struct.
// If an environment variable is not set, it falls back to a safe default.
//
// In Go, functions that start with an uppercase letter are "exported" (public).
// Functions starting with lowercase are "unexported" (private to the package).
func Load() *Config {
	// The & operator returns a pointer to the Config struct.
	// Returning a pointer is idiomatic in Go for structs because:
	//   1. It avoids copying the entire struct (performance)
	//   2. It signals that the caller gets the "real" config, not a copy
	return &Config{
		Port:           getEnvInt("PORT", 8080),
		Environment:    getEnvStr("ENVIRONMENT", "development"),
		JWTSecret:      getEnvStr("JWT_SECRET", "CHANGE-ME-IN-PRODUCTION"),
		RateLimitRPS:   getEnvInt("RATE_LIMIT_RPS", 10),
		AllowedOrigins: getEnvStr("ALLOWED_ORIGINS", "*"),
	}
}

// getEnvStr reads a string environment variable, returning the fallback if not set.
// This is a helper function — unexported (lowercase) because only this package uses it.
func getEnvStr(key, fallback string) string {
	// os.Getenv returns the value of an environment variable, or "" if not set.
	// In Go, we often use the short variable declaration := which infers the type.
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// getEnvInt reads an integer environment variable, returning the fallback if not set
// or if the value cannot be parsed as an integer.
func getEnvInt(key string, fallback int) int {
	// os.Getenv always returns a string, so we need to convert to int.
	// strconv.Atoi converts a string to an int ("Atoi" = "ASCII to integer").
	// It returns two values: the integer and an error.
	// In Go, functions commonly return (result, error) — this is called the
	// "error return pattern" and is Go's primary error handling mechanism.
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	// If Atoi fails (e.g., the env var is "abc" instead of "8080"),
	// we silently fall back to the default. In production, you might want
	// to log a warning here.
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return intValue
}
