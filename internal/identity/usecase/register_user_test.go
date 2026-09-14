package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
)

func mustHash(t *testing.T, b []byte) domain.PasswordHash {
	t.Helper()

	h, err := domain.NewPasswordHash(b)
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}

	return h
}

func TestRegisterUserHandler(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	genID := uuid.Must(uuid.NewV7())
	hasherErr := errors.New("argon2 failed")
	idgenErr := errors.New("entropy exhausted")

	tests := []struct {
		name    string
		cmd     RegisterUserCommand
		creator *fakeUserCreator
		hasher  *fakeHasher
		ids     fakeIDGen
		wantErr error
	}{
		{
			name:    "success",
			cmd:     RegisterUserCommand{Login: "  Alice  ", Password: "correct horse battery"},
			creator: &fakeUserCreator{},
			hasher:  &fakeHasher{hash: mustHash(t, []byte("hashed"))},
			ids:     fakeIDGen{id: genID},
		},
		{
			name:    "invalid login",
			cmd:     RegisterUserCommand{Login: "a!", Password: "correct horse battery"},
			creator: &fakeUserCreator{},
			hasher:  &fakeHasher{hash: mustHash(t, []byte("hashed"))},
			ids:     fakeIDGen{id: genID},
			wantErr: domain.ErrInvalidLogin,
		},
		{
			name:    "weak password",
			cmd:     RegisterUserCommand{Login: "alice", Password: "short"},
			creator: &fakeUserCreator{},
			hasher:  &fakeHasher{hash: mustHash(t, []byte("hashed"))},
			ids:     fakeIDGen{id: genID},
			wantErr: domain.ErrWeakPassword,
		},
		{
			name:    "login taken",
			cmd:     RegisterUserCommand{Login: "alice", Password: "correct horse battery"},
			creator: &fakeUserCreator{err: domain.ErrLoginTaken},
			hasher:  &fakeHasher{hash: mustHash(t, []byte("hashed"))},
			ids:     fakeIDGen{id: genID},
			wantErr: domain.ErrLoginTaken,
		},
		{
			name:    "hasher failure",
			cmd:     RegisterUserCommand{Login: "alice", Password: "correct horse battery"},
			creator: &fakeUserCreator{},
			hasher:  &fakeHasher{err: hasherErr},
			ids:     fakeIDGen{id: genID},
			wantErr: hasherErr,
		},
		{
			name:    "idgen failure",
			cmd:     RegisterUserCommand{Login: "alice", Password: "correct horse battery"},
			creator: &fakeUserCreator{},
			hasher:  &fakeHasher{hash: mustHash(t, []byte("hashed"))},
			ids:     fakeIDGen{err: idgenErr},
			wantErr: idgenErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewRegisterUserHandler(tt.creator, tt.hasher, fixedClock{now: now}, tt.ids)

			// Act
			got, err := h.Handle(context.Background(), tt.cmd)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Handle error = %v, want %v", err, tt.wantErr)
				}
				if tt.creator.err == nil && len(tt.creator.created) != 0 {
					t.Fatal("user must not be created on failure")
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle unexpected error: %v", err)
			}

			if got.UserID != genID.String() {
				t.Fatalf("UserID = %q, want %q", got.UserID, genID.String())
			}

			if len(tt.creator.created) != 1 {
				t.Fatalf("created users = %d, want 1", len(tt.creator.created))
			}

			saved := tt.creator.created[0]
			if saved.Login().String() != "alice" {
				t.Fatalf("saved login = %q, want %q", saved.Login().String(), "alice")
			}

			if string(saved.PasswordHash().Bytes()) != "hashed" {
				t.Fatal("saved hash does not match hasher output")
			}

			if !saved.CreatedAt().Equal(now) {
				t.Fatalf("saved createdAt = %v, want %v", saved.CreatedAt(), now)
			}
		})
	}
}
