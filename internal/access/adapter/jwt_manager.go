package adapter

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/golang-jwt/jwt/v5"
)

const minSecretLen = 32

var ErrWeakJWTSecret = errors.New("jwt secret is too short")

type JWTManager struct {
	secret []byte
	ttl    time.Duration
	clock  clock.Clock
}

func NewJWTManager(secret []byte, ttl time.Duration, clk clock.Clock) (JWTManager, error) {
	if len(secret) < minSecretLen {
		return JWTManager{}, ErrWeakJWTSecret
	}

	if ttl <= 0 {
		return JWTManager{}, domain.ErrInvalidTokenTTL
	}

	return JWTManager{secret: append([]byte(nil), secret...), ttl: ttl, clock: clk}, nil
}

func (m JWTManager) Issue(_ context.Context, userID vo.UserID, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(m.ttl)
	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign token: %w", err)
	}

	return signed, expiresAt, nil
}

func (m JWTManager) Verify(_ context.Context, token string) (vo.UserID, error) {
	parsed, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{},
		func(*jwt.Token) (any, error) { return m.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithTimeFunc(m.clock.Now),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return vo.UserID{}, domain.ErrAccessTokenExpired
		}
		return vo.UserID{}, domain.ErrInvalidAccessToken
	}

	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return vo.UserID{}, domain.ErrInvalidAccessToken
	}

	userID, err := vo.ParseUserID(claims.Subject)
	if err != nil {
		return vo.UserID{}, domain.ErrInvalidAccessToken
	}

	return userID, nil
}
