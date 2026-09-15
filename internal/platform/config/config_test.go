package config

import (
	"testing"
	"time"
)

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_DSN", "postgres://env")
	t.Setenv("JWT_SECRET", "env-secret")
}

func TestLoadDefaults(t *testing.T) {
	// Arrange
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
}

func TestLoadOverrides(t *testing.T) {
	// Arrange
	setRequired(t)
	t.Setenv("GRPC_ADDRESS", ":9090")
	t.Setenv("ACCESS_TOKEN_TTL", "5m")
	t.Setenv("LOG_FORMAT", "text")

	// Act
	cfg, err := Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GRPCAddress != ":9090" || cfg.AccessTokenTTL != 5*time.Minute || cfg.LogFormat != "text" {
		t.Fatalf("overrides not applied: %+v", cfg)
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
			t.Setenv("DATABASE_DSN", "postgres://x")
			t.Setenv("JWT_SECRET", "s")
			t.Setenv("ACCESS_TOKEN_TTL", "nonsense")
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
