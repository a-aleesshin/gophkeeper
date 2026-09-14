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

func TestUpdateSecretHandler(t *testing.T) {
	// Arrange
	created := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	updatedAt := created.Add(time.Hour)
	owner := mustOwnerID(t)

	tests := []struct {
		name    string
		prepare func(*fakeStore) UpdateSecretCommand
		wantErr error
		wantVer int64
	}{
		{
			name: "success",
			prepare: func(st *fakeStore) UpdateSecretCommand {
				s := mustSecret(t, owner, created)
				st.secrets[s.ID().String()] = s
				return UpdateSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Payload: []byte("v2"), Version: 1}
			},
			wantVer: 2,
		},
		{
			name: "version conflict",
			prepare: func(st *fakeStore) UpdateSecretCommand {
				s := mustSecret(t, owner, created)
				st.secrets[s.ID().String()] = s
				return UpdateSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Payload: []byte("v2"), Version: 5}
			},
			wantErr: domain.ErrVersionConflict,
		},
		{
			name: "deleted secret",
			prepare: func(st *fakeStore) UpdateSecretCommand {
				s := mustSecret(t, owner, created)
				deleted, err := s.Delete(1, created)
				if err != nil {
					t.Fatalf("Delete: %v", err)
				}
				st.secrets[s.ID().String()] = deleted
				return UpdateSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Payload: []byte("v2"), Version: 2}
			},
			wantErr: domain.ErrSecretDeleted,
		},
		{
			name: "not found",
			prepare: func(*fakeStore) UpdateSecretCommand {
				return UpdateSecretCommand{OwnerID: owner, SecretID: uuid.Must(uuid.NewV7()).String(), Payload: []byte("v2"), Version: 1}
			},
			wantErr: domain.ErrSecretNotFound,
		},
		{
			name: "foreign owner",
			prepare: func(st *fakeStore) UpdateSecretCommand {
				s := mustSecret(t, mustOwnerID(t), created)
				st.secrets[s.ID().String()] = s
				return UpdateSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Payload: []byte("v2"), Version: 1}
			},
			wantErr: domain.ErrSecretNotFound,
		},
		{
			name: "empty payload",
			prepare: func(st *fakeStore) UpdateSecretCommand {
				s := mustSecret(t, owner, created)
				st.secrets[s.ID().String()] = s
				return UpdateSecretCommand{OwnerID: owner, SecretID: s.ID().String(), Version: 1}
			},
			wantErr: domain.ErrEmptyPayload,
		},
		{
			name: "zero owner",
			prepare: func(*fakeStore) UpdateSecretCommand {
				return UpdateSecretCommand{SecretID: uuid.Must(uuid.NewV7()).String(), Payload: []byte("v2"), Version: 1}
			},
			wantErr: vo.ErrInvalidUserID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			cmd := tt.prepare(store)
			h := NewUpdateSecretHandler(store, store, fixedClock{now: updatedAt})

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
			if string(saved.Payload().Bytes()) != "v2" {
				t.Fatalf("saved payload = %q, want v2", saved.Payload().Bytes())
			}

			if !saved.UpdatedAt().Equal(updatedAt) {
				t.Fatalf("saved updatedAt = %v, want %v", saved.UpdatedAt(), updatedAt)
			}
		})
	}
}
