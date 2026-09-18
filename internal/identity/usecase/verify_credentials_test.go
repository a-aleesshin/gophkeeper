package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

func makeUser(t *testing.T) domain.User {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}

	login, err := domain.NewLogin("alice")
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}

	user, err := domain.NewUser(id, login, mustHash(t, []byte("real-hash")), time.Now().UTC())
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}

	return user
}

func TestVerifyCredentialsHandler(t *testing.T) {
	// Arrange
	user := makeUser(t)
	dummy := mustHash(t, []byte("dummy-hash"))
	storageErr := errors.New("connection refused")
	compareErr := errors.New("argon2 failed")

	tests := []struct {
		name         string
		cmd          VerifyCredentialsCommand
		provider     *fakeUserProvider
		verifier     *fakeVerifier
		wantErr      error
		wantCompares int
		wantDummy    bool
	}{
		{
			name:         "success",
			cmd:          VerifyCredentialsCommand{Login: "Alice", Password: "correct horse battery"},
			provider:     &fakeUserProvider{user: user},
			verifier:     &fakeVerifier{ok: true},
			wantCompares: 1,
		},
		{
			name:         "wrong password",
			cmd:          VerifyCredentialsCommand{Login: "alice", Password: "wrong password 123"},
			provider:     &fakeUserProvider{user: user},
			verifier:     &fakeVerifier{ok: false},
			wantErr:      domain.ErrInvalidCredentials,
			wantCompares: 1,
		},
		{
			name:         "user not found runs dummy compare",
			cmd:          VerifyCredentialsCommand{Login: "ghost", Password: "correct horse battery"},
			provider:     &fakeUserProvider{err: domain.ErrUserNotFound},
			verifier:     &fakeVerifier{ok: false},
			wantErr:      domain.ErrInvalidCredentials,
			wantCompares: 1,
			wantDummy:    true,
		},
		{
			name:         "invalid login format",
			cmd:          VerifyCredentialsCommand{Login: "a!", Password: "correct horse battery"},
			provider:     &fakeUserProvider{user: user},
			verifier:     &fakeVerifier{ok: true},
			wantErr:      domain.ErrInvalidCredentials,
			wantCompares: 0,
		},
		{
			name:         "short password",
			cmd:          VerifyCredentialsCommand{Login: "alice", Password: "short"},
			provider:     &fakeUserProvider{user: user},
			verifier:     &fakeVerifier{ok: true},
			wantErr:      domain.ErrInvalidCredentials,
			wantCompares: 0,
		},
		{
			name:         "storage failure",
			cmd:          VerifyCredentialsCommand{Login: "alice", Password: "correct horse battery"},
			provider:     &fakeUserProvider{err: storageErr},
			verifier:     &fakeVerifier{ok: true},
			wantErr:      storageErr,
			wantCompares: 0,
		},
		{
			name:         "compare failure",
			cmd:          VerifyCredentialsCommand{Login: "alice", Password: "correct horse battery"},
			provider:     &fakeUserProvider{user: user},
			verifier:     &fakeVerifier{err: compareErr},
			wantErr:      compareErr,
			wantCompares: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewVerifyCredentialsHandler(tt.provider, tt.verifier, dummy)

			// Act
			got, err := h.Handle(context.Background(), tt.cmd)

			// Assert
			if len(tt.verifier.compared) != tt.wantCompares {
				t.Fatalf("Compare calls = %d, want %d", len(tt.verifier.compared), tt.wantCompares)
			}

			if tt.wantDummy {
				if string(tt.verifier.compared[0].Bytes()) != "dummy-hash" {
					t.Fatal("expected dummy hash in Compare call")
				}
			}

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Handle error = %v, want %v", err, tt.wantErr)
				}
				if !got.UserID.IsZero() {
					t.Fatal("failed Handle must not return user id")
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle unexpected error: %v", err)
			}

			if got.UserID != user.ID() {
				t.Fatalf("UserID = %v, want %v", got.UserID, user.ID())
			}
		})
	}
}
