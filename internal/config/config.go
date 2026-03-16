// Package config handles application configuration loaded from environment variables.
package config

import (
	"os"
	"strconv"
)

// Config holds all application configuration.
type Config struct {
	Port           int
	Environment    string
	JWTSecret      string // Symmetric key for JWT signing; use asymmetric (RS256) in production.
	JWTExpiration  int    // Token expiration in minutes.
	RateLimitRPS   int
	AllowedOrigins string
}

// Load reads configuration from environment variables with safe defaults.
func Load() *Config {
	return &Config{
		Port:           getEnvInt("PORT", 8080),
		Environment:    getEnvStr("ENVIRONMENT", "development"),
		JWTSecret:      getEnvStr("JWT_SECRET", "CHANGE-ME-IN-PRODUCTION"),
		JWTExpiration:  getEnvInt("JWT_EXPIRATION_MINUTES", 60),
		RateLimitRPS:   getEnvInt("RATE_LIMIT_RPS", 10),
		AllowedOrigins: getEnvStr("ALLOWED_ORIGINS", "*"),
	}
}

func getEnvStr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return intValue
}
