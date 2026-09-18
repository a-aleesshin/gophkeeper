package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

func mustUserID(t *testing.T) vo.UserID {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return id
}

func mustLogin(t *testing.T, s string) Login {
	t.Helper()
	l, err := NewLogin(s)
	if err != nil {
		t.Fatalf("NewLogin(%q): %v", s, err)
	}
	return l
}

func mustPasswordHash(t *testing.T, b []byte) PasswordHash {
	t.Helper()
	h, err := NewPasswordHash(b)
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	return h
}

func TestNewUser(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	validID := mustUserID(t)
	validLogin := mustLogin(t, "alice")
	validHash := mustPasswordHash(t, []byte("argon2id$hash"))

	tests := []struct {
		name    string
		id      vo.UserID
		login   Login
		hash    PasswordHash
		wantErr error
	}{
		{name: "valid", id: validID, login: validLogin, hash: validHash},
		{name: "zero id", id: vo.UserID{}, login: validLogin, hash: validHash, wantErr: vo.ErrInvalidUserID},
		{name: "zero login", id: validID, login: Login{}, hash: validHash, wantErr: ErrInvalidLogin},
		{name: "zero hash", id: validID, login: validLogin, hash: PasswordHash{}, wantErr: ErrEmptyPasswordHash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewUser(tt.id, tt.login, tt.hash, now)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewUser error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewUser unexpected error: %v", err)
			}
			if got.ID() != tt.id {
				t.Fatalf("ID() = %v, want %v", got.ID(), tt.id)
			}
			if got.Login() != tt.login {
				t.Fatalf("Login() = %v, want %v", got.Login(), tt.login)
			}
			if !got.CreatedAt().Equal(now) {
				t.Fatalf("CreatedAt() = %v, want %v", got.CreatedAt(), now)
			}
		})
	}
}

func TestRestoreUser(t *testing.T) {
	// Arrange
	id := mustUserID(t)
	login := mustLogin(t, "alice")
	hash := mustPasswordHash(t, []byte("argon2id$hash"))
	createdAt := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Act
	got := RestoreUser(id, login, hash, createdAt)

	// Assert
	if got.ID() != id {
		t.Fatalf("ID() = %v, want %v", got.ID(), id)
	}
	if got.Login() != login {
		t.Fatalf("Login() = %v, want %v", got.Login(), login)
	}
	if string(got.PasswordHash().Bytes()) != string(hash.Bytes()) {
		t.Fatal("PasswordHash() does not match restored value")
	}
	if !got.CreatedAt().Equal(createdAt) {
		t.Fatalf("CreatedAt() = %v, want %v", got.CreatedAt(), createdAt)
	}
}

func TestPasswordHashImmutability(t *testing.T) {
	// Arrange
	raw := []byte("argon2id$hash")
	h := mustPasswordHash(t, raw)

	// Act
	raw[0] = 'X'
	leaked := h.Bytes()
	leaked[1] = 'Y'

	// Assert
	if string(h.Bytes()) != "argon2id$hash" {
		t.Fatalf("PasswordHash mutated through shared slice: %q", h.Bytes())
	}
}

func TestPasswordHashDoesNotLeakInFormatting(t *testing.T) {
	// Arrange
	const secret = "argon2id$super-secret-hash"
	h := mustPasswordHash(t, []byte(secret))

	// Act
	formatted := []string{
		fmt.Sprintf("%v", h),
		fmt.Sprintf("%+v", h),
		fmt.Sprintf("%s", h),
		fmt.Sprint(h),
	}

	// Assert
	for _, out := range formatted {
		if strings.Contains(out, secret) {
			t.Fatalf("formatted output leaks hash: %q", out)
		}
	}
}
