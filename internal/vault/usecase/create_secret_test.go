package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

func TestCreateSecretHandler(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	owner := mustOwnerID(t)
	secretID := uuid.Must(uuid.NewV7()).String()

	validCmd := func() CreateSecretCommand {
		return CreateSecretCommand{
			OwnerID:  owner,
			SecretID: secretID,
			Type:     "credentials",
			Payload:  []byte("ciphertext"),
			Metadata: []byte("encrypted-meta"),
		}
	}

	tests := []struct {
		name    string
		mutate  func(*CreateSecretCommand)
		creator *fakeSecretCreator
		wantErr error
	}{
		{name: "success", mutate: func(*CreateSecretCommand) {}, creator: &fakeSecretCreator{}},
		{
			name:    "invalid secret id",
			mutate:  func(c *CreateSecretCommand) { c.SecretID = "not-a-uuid" },
			creator: &fakeSecretCreator{},
			wantErr: domain.ErrInvalidSecretID,
		},
		{
			name:    "unknown type",
			mutate:  func(c *CreateSecretCommand) { c.Type = "totp" },
			creator: &fakeSecretCreator{},
			wantErr: domain.ErrUnknownSecretType,
		},
		{
			name:    "empty payload",
			mutate:  func(c *CreateSecretCommand) { c.Payload = nil },
			creator: &fakeSecretCreator{},
			wantErr: domain.ErrEmptyPayload,
		},
		{
			name:    "oversized metadata",
			mutate:  func(c *CreateSecretCommand) { c.Metadata = make([]byte, domain.MaxMetadataSize+1) },
			creator: &fakeSecretCreator{},
			wantErr: domain.ErrMetadataTooLarge,
		},
		{
			name:    "zero owner",
			mutate:  func(c *CreateSecretCommand) { c.OwnerID = vo.UserID{} },
			creator: &fakeSecretCreator{},
			wantErr: vo.ErrInvalidUserID,
		},
		{
			name:    "duplicate id",
			mutate:  func(*CreateSecretCommand) {},
			creator: &fakeSecretCreator{err: domain.ErrSecretAlreadyExists},
			wantErr: domain.ErrSecretAlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := validCmd()
			tt.mutate(&cmd)
			h := NewCreateSecretHandler(tt.creator, fixedClock{now: now})

			// Act
			got, err := h.Handle(context.Background(), cmd)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Handle error = %v, want %v", err, tt.wantErr)
				}
				if tt.creator.err == nil && len(tt.creator.created) != 0 {
					t.Fatal("secret must not be created on failure")
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle unexpected error: %v", err)
			}

			if got.Version != 1 {
				t.Fatalf("Version = %d, want 1", got.Version)
			}

			if len(tt.creator.created) != 1 {
				t.Fatalf("created secrets = %d, want 1", len(tt.creator.created))
			}

			saved := tt.creator.created[0]
			if saved.ID().String() != secretID {
				t.Fatalf("saved id = %s, want %s", saved.ID(), secretID)
			}

			if saved.OwnerID() != owner {
				t.Fatalf("saved owner = %v, want %v", saved.OwnerID(), owner)
			}

			if saved.Type() != domain.SecretTypeCredentials {
				t.Fatalf("saved type = %s", saved.Type())
			}

			if string(saved.Payload().Bytes()) != "ciphertext" {
				t.Fatal("saved payload mismatch")
			}

			if !saved.CreatedAt().Equal(now) {
				t.Fatalf("saved createdAt = %v, want %v", saved.CreatedAt(), now)
			}
		})
	}
}
