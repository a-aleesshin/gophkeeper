package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

func TestDeleteSecretHandler(t *testing.T) {
	// Arrange
	created := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	deletedAt := created.Add(time.Hour)
	owner := mustOwnerID(t)

	tests := []struct {
		name    string
		prepare func(*fakeStore) DeleteSecretCommand
		wantErr error
		wantVer int64
	}{
		{
			name: "success",
			prepare: func(st *fakeStore) DeleteSecretCommand {
				s := mustSecret(t, owner, created)
				st.secrets[s.ID().String()] = s
				return DeleteSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Version: 1}
			},
			wantVer: 2,
		},
		{
			name: "already deleted is idempotent",
			prepare: func(st *fakeStore) DeleteSecretCommand {
				s := mustSecret(t, owner, created)
				deleted, err := s.Delete(1, created)
				if err != nil {
					t.Fatalf("Delete: %v", err)
				}
				st.secrets[s.ID().String()] = deleted
				return DeleteSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Version: 99}
			},
			wantVer: 2,
		},
		{
			name: "version conflict",
			prepare: func(st *fakeStore) DeleteSecretCommand {
				s := mustSecret(t, owner, created)
				st.secrets[s.ID().String()] = s
				return DeleteSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Version: 5}
			},
			wantErr: domain.ErrVersionConflict,
		},
		{
			name: "not found",
			prepare: func(*fakeStore) DeleteSecretCommand {
				return DeleteSecretCommand{OwnerID: owner, SecretID: uuid.Must(uuid.NewV7()).String(), Version: 1}
			},
			wantErr: domain.ErrSecretNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			cmd := tt.prepare(store)
			h := NewDeleteSecretHandler(store, store, fixedClock{now: deletedAt})

			// Act
			got, err := h.Handle(context.Background(), cmd)

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
			if got.Version != tt.wantVer {
				t.Fatalf("Version = %d, want %d", got.Version, tt.wantVer)
			}
			saved := store.secrets[cmd.SecretID]
			if !saved.IsDeleted() {
				t.Fatal("secret is not deleted in store")
			}
			if !saved.Payload().IsZero() {
				t.Fatal("tombstone still holds payload")
			}
		})
	}
}
