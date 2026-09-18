package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

const minTokenTTL = time.Minute

type Config struct {
	GRPCAddress         string
	DatabaseDSN         string
	JWTSecret           string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	LogLevel            string
	LogFormat           string
	AuthRateLimitPerSec int
	AuthRateLimitBurst  int
}

func Load() (Config, error) {
	cfg := Config{
		GRPCAddress:         getenv("GRPC_ADDRESS", ":50051"),
		DatabaseDSN:         os.Getenv("DATABASE_DSN"),
		JWTSecret:           os.Getenv("JWT_SECRET"),
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		LogLevel:            getenv("LOG_LEVEL", "info"),
		LogFormat:           getenv("LOG_FORMAT", "json"),
		AuthRateLimitPerSec: 1,
		AuthRateLimitBurst:  5,
	}

	if cfg.DatabaseDSN == "" {
		return Config{}, errors.New("DATABASE_DSN is required")
	}
	if cfg.JWTSecret == "" {
		return Config{}, errors.New("JWT_SECRET is required")
	}

	var err error
	if cfg.AccessTokenTTL, err = durationEnv("ACCESS_TOKEN_TTL", cfg.AccessTokenTTL); err != nil {
		return Config{}, err
	}
	if cfg.RefreshTokenTTL, err = durationEnv("REFRESH_TOKEN_TTL", cfg.RefreshTokenTTL); err != nil {
		return Config{}, err
	}
	if cfg.AuthRateLimitPerSec, err = intEnv("AUTH_RATE_LIMIT_PER_SEC", cfg.AuthRateLimitPerSec); err != nil {
		return Config{}, err
	}
	if cfg.AuthRateLimitBurst, err = intEnv("AUTH_RATE_LIMIT_BURST", cfg.AuthRateLimitBurst); err != nil {
		return Config{}, err
	}

	if cfg.AccessTokenTTL < minTokenTTL {
		return Config{}, fmt.Errorf("ACCESS_TOKEN_TTL must be at least %s", minTokenTTL)
	}
	if cfg.RefreshTokenTTL < cfg.AccessTokenTTL {
		return Config{}, errors.New("REFRESH_TOKEN_TTL must not be shorter than ACCESS_TOKEN_TTL")
	}
	if cfg.AuthRateLimitPerSec < 1 || cfg.AuthRateLimitBurst < 1 {
		return Config{}, errors.New("auth rate limit values must be positive")
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return d, nil
}

func intEnv(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	return n, nil
}
