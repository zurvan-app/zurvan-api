package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	Port        string
	Database    DatabaseConfig
	JWT         JWTConfig
	Environment string
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	ConnectionURL string
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// Load loads configuration from environment variables
func Load() *Config {
	return &Config{
		Port:        getEnv("PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),
		Database: DatabaseConfig{
			ConnectionURL: getEnv("DB_CONNECTION_URL", ""),
		},
		JWT: JWTConfig{
			Secret:          getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-this-in-production"),
			AccessTokenTTL:  getDurationEnv("JWT_ACCESS_TOKEN_TTL", 15*time.Minute),
			RefreshTokenTTL: getDurationEnv("JWT_REFRESH_TOKEN_TTL", 7*24*time.Hour),
		},
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getDurationEnv gets a duration from environment variable or returns a default value
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultValue
}
