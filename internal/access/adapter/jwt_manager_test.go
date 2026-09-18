package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time { return f.now }

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func mustUserID(t *testing.T) vo.UserID {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return id
}

func TestNewJWTManagerValidation(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		secret  []byte
		ttl     time.Duration
		wantErr error
	}{
		{name: "valid", secret: testSecret, ttl: time.Minute},
		{name: "short secret", secret: []byte("short"), ttl: time.Minute, wantErr: ErrWeakJWTSecret},
		{name: "zero ttl", secret: testSecret, ttl: 0, wantErr: domain.ErrInvalidTokenTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			_, err := NewJWTManager(tt.secret, tt.ttl, fixedClock{})

			// Assert
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewJWTManager error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestJWTManagerRoundtrip(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	userID := mustUserID(t)
	m, err := NewJWTManager(testSecret, 15*time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	// Act
	token, expiresAt, err := m.Issue(context.Background(), userID, now)

	// Assert
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !expiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, now.Add(15*time.Minute))
	}

	got, err := m.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != userID {
		t.Fatalf("Verify = %v, want %v", got, userID)
	}
}

func TestJWTManagerExpiredToken(t *testing.T) {
	// Arrange
	issued := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	userID := mustUserID(t)
	issuer, err := NewJWTManager(testSecret, 15*time.Minute, fixedClock{now: issued})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	token, _, err := issuer.Issue(context.Background(), userID, issued)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	verifier, err := NewJWTManager(testSecret, 15*time.Minute, fixedClock{now: issued.Add(16 * time.Minute)})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	// Act
	_, err = verifier.Verify(context.Background(), token)

	// Assert
	if !errors.Is(err, domain.ErrAccessTokenExpired) {
		t.Fatalf("Verify error = %v, want ErrAccessTokenExpired", err)
	}
}

func TestJWTManagerInvalidTokens(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	userID := mustUserID(t)

	m, err := NewJWTManager(testSecret, 15*time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	otherSecret := []byte("ffffffffffffffffffffffffffffffff")
	other, err := NewJWTManager(otherSecret, 15*time.Minute, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	foreignToken, _, err := other.Issue(context.Background(), userID, now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	ownToken, _, err := m.Issue(context.Background(), userID, now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{name: "garbage", token: "not.a.jwt"},
		{name: "empty", token: ""},
		{name: "wrong secret", token: foreignToken},
		{name: "tampered payload", token: ownToken[:len(ownToken)-4] + "AAAA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			_, err := m.Verify(context.Background(), tt.token)

			// Assert
			if !errors.Is(err, domain.ErrInvalidAccessToken) {
				t.Fatalf("Verify error = %v, want ErrInvalidAccessToken", err)
			}
		})
	}
}
