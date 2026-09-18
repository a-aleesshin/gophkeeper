package usecase

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

func TestGetSecretHandler(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	owner := mustOwnerID(t)
	secret := mustSecret(t, owner, now)
	deletedSecret, err := secret.Delete(1, now.Add(time.Hour))

	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	storageErr := errors.New("connection refused")

	tests := []struct {
		name     string
		query    GetSecretQuery
		provider *fakeSecretProvider
		wantErr  error
	}{
		{
			name:     "success",
			query:    GetSecretQuery{OwnerID: owner, SecretID: secret.ID().String()},
			provider: &fakeSecretProvider{secret: secret},
		},
		{
			name:     "zero owner",
			query:    GetSecretQuery{SecretID: secret.ID().String()},
			provider: &fakeSecretProvider{secret: secret},
			wantErr:  vo.ErrInvalidUserID,
		},
		{
			name:     "invalid secret id",
			query:    GetSecretQuery{OwnerID: owner, SecretID: "not-a-uuid"},
			provider: &fakeSecretProvider{secret: secret},
			wantErr:  domain.ErrInvalidSecretID,
		},
		{
			name:     "not found",
			query:    GetSecretQuery{OwnerID: owner, SecretID: uuid.Must(uuid.NewV7()).String()},
			provider: &fakeSecretProvider{err: domain.ErrSecretNotFound},
			wantErr:  domain.ErrSecretNotFound,
		},
		{
			name:     "deleted secret hidden",
			query:    GetSecretQuery{OwnerID: owner, SecretID: secret.ID().String()},
			provider: &fakeSecretProvider{secret: deletedSecret},
			wantErr:  domain.ErrSecretNotFound,
		},
		{
			name:     "storage failure",
			query:    GetSecretQuery{OwnerID: owner, SecretID: secret.ID().String()},
			provider: &fakeSecretProvider{err: storageErr},
			wantErr:  storageErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewGetSecretHandler(tt.provider)

			// Act
			got, err := h.Handle(context.Background(), tt.query)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Handle error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle unexpected error: %v", err)
			}

			if got.SecretID != secret.ID().String() {
				t.Fatalf("SecretID = %s, want %s", got.SecretID, secret.ID())
			}

			if got.Type != "credentials" {
				t.Fatalf("Type = %s, want credentials", got.Type)
			}

			if !bytes.Equal(got.Payload, secret.Payload().Bytes()) {
				t.Fatal("Payload mismatch")
			}

			if !bytes.Equal(got.Metadata, secret.Metadata().Bytes()) {
				t.Fatal("Metadata mismatch")
			}

			if got.Version != 1 {
				t.Fatalf("Version = %d, want 1", got.Version)
			}
			
			if !got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
				t.Fatalf("timestamps = %v/%v, want %v", got.CreatedAt, got.UpdatedAt, now)
			}
		})
	}
}
