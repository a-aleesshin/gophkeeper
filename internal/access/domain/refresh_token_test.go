package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

func mustTokenID(t *testing.T) TokenID {
	t.Helper()
	id, err := TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("TokenIDFromUUID: %v", err)
	}
	return id
}

func mustUserID(t *testing.T) vo.UserID {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return id
}

func mustHash(t *testing.T) TokenHash {
	t.Helper()
	h, err := NewTokenHash([]byte("sha256-of-token"))
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}
	return h
}

func TestNewRefreshToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	ttl := time.Hour
	validID := mustTokenID(t)
	validUser := mustUserID(t)
	validHash := mustHash(t)

	tests := []struct {
		name    string
		id      TokenID
		user    vo.UserID
		hash    TokenHash
		ttl     time.Duration
		wantErr error
	}{
		{name: "valid", id: validID, user: validUser, hash: validHash, ttl: ttl},
		{name: "zero id", id: TokenID{}, user: validUser, hash: validHash, ttl: ttl, wantErr: ErrInvalidTokenID},
		{name: "zero user", id: validID, user: vo.UserID{}, hash: validHash, ttl: ttl, wantErr: vo.ErrInvalidUserID},
		{name: "zero hash", id: validID, user: validUser, hash: TokenHash{}, ttl: ttl, wantErr: ErrEmptyTokenHash},
		{name: "zero ttl", id: validID, user: validUser, hash: validHash, ttl: 0, wantErr: ErrInvalidTokenTTL},
		{name: "negative ttl", id: validID, user: validUser, hash: validHash, ttl: -time.Hour, wantErr: ErrInvalidTokenTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewRefreshToken(tt.id, tt.user, tt.hash, now, tt.ttl)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewRefreshToken error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewRefreshToken unexpected error: %v", err)
			}
			if !got.ExpiresAt().Equal(now.Add(ttl)) {
				t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt(), now.Add(ttl))
			}
			if !got.CreatedAt().Equal(now) {
				t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt(), now)
			}
		})
	}
}

func TestRefreshTokenIsExpired(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	token, err := NewRefreshToken(mustTokenID(t), mustUserID(t), mustHash(t), now, time.Hour)
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}

	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{name: "before expiry", at: now.Add(59 * time.Minute), want: false},
		{name: "exactly at expiry", at: now.Add(time.Hour), want: true},
		{name: "after expiry", at: now.Add(2 * time.Hour), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got := token.IsExpired(tt.at)

			// Assert
			if got != tt.want {
				t.Fatalf("IsExpired(%v) = %v, want %v", tt.at, got, tt.want)
			}
		})
	}
}
