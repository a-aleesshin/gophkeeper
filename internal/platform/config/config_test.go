package config

import (
	"testing"
	"time"
)

var allKeys = []string{
	"GRPC_ADDRESS", "DATABASE_DSN", "JWT_SECRET",
	"ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL",
	"LOG_LEVEL", "LOG_FORMAT",
	"AUTH_RATE_LIMIT_PER_SEC", "AUTH_RATE_LIMIT_BURST",
}

func isolateEnv(t *testing.T) {
	t.Helper()
	for _, key := range allKeys {
		t.Setenv(key, "")
	}
}

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_DSN", "postgres://env")
	t.Setenv("JWT_SECRET", "env-secret")
}

func TestLoadDefaults(t *testing.T) {
	// Arrange
	isolateEnv(t)
	setRequired(t)

	// Act
	cfg, err := Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GRPCAddress != ":50051" || cfg.AccessTokenTTL != 15*time.Minute ||
		cfg.RefreshTokenTTL != 30*24*time.Hour || cfg.LogFormat != "json" || cfg.LogLevel != "info" {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.AuthRateLimitPerSec != 1 || cfg.AuthRateLimitBurst != 5 {
		t.Fatalf("rate limit defaults not applied: %+v", cfg)
	}
}

func TestLoadOverrides(t *testing.T) {
	// Arrange
	isolateEnv(t)
	setRequired(t)
	t.Setenv("GRPC_ADDRESS", ":9090")
	t.Setenv("ACCESS_TOKEN_TTL", "5m")
	t.Setenv("LOG_FORMAT", "text")
	t.Setenv("AUTH_RATE_LIMIT_PER_SEC", "10")
	t.Setenv("AUTH_RATE_LIMIT_BURST", "20")

	// Act
	cfg, err := Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GRPCAddress != ":9090" || cfg.AccessTokenTTL != 5*time.Minute || cfg.LogFormat != "text" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if cfg.AuthRateLimitPerSec != 10 || cfg.AuthRateLimitBurst != 20 {
		t.Fatalf("rate limit overrides not applied: %+v", cfg)
	}
}

func TestLoadValidation(t *testing.T) {
	// Arrange
	tests := []struct {
		name  string
		setup func(*testing.T)
	}{
		{name: "missing dsn", setup: func(t *testing.T) { t.Setenv("JWT_SECRET", "s") }},
		{name: "missing jwt secret", setup: func(t *testing.T) { t.Setenv("DATABASE_DSN", "postgres://x") }},
		{name: "bad duration", setup: func(t *testing.T) {
			setRequired(t)
			t.Setenv("ACCESS_TOKEN_TTL", "nonsense")
		}},
		{name: "access ttl below minimum", setup: func(t *testing.T) {
			setRequired(t)
			t.Setenv("ACCESS_TOKEN_TTL", "1ns")
		}},
		{name: "refresh ttl below minimum", setup: func(t *testing.T) {
			setRequired(t)
			t.Setenv("REFRESH_TOKEN_TTL", "30s")
		}},
		{name: "bad rate limit", setup: func(t *testing.T) {
			setRequired(t)
			t.Setenv("AUTH_RATE_LIMIT_PER_SEC", "zero")
		}},
		{name: "zero burst", setup: func(t *testing.T) {
			setRequired(t)
			t.Setenv("AUTH_RATE_LIMIT_BURST", "0")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateEnv(t)
			tt.setup(t)

			// Act
			_, err := Load()

			// Assert
			if err == nil {
				t.Fatal("Load accepted invalid config")
			}
		})
	}
}
