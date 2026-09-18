package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

func mustSecretID(t *testing.T) SecretID {
	t.Helper()

	id, err := SecretIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("SecretIDFromUUID: %v", err)
	}

	return id
}

func mustOwnerID(t *testing.T) vo.UserID {
	t.Helper()

	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}

	return id
}

func mustPayload(t *testing.T, b []byte) Payload {
	t.Helper()

	p, err := NewPayload(b)
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}

	return p
}

func mustSecret(t *testing.T, now time.Time) Secret {
	t.Helper()

	s, err := NewSecret(mustSecretID(t), mustOwnerID(t), SecretTypeCredentials, mustPayload(t, []byte("v1")), Metadata{}, now)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	return s
}

func TestNewSecret(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	validID := mustSecretID(t)
	validOwner := mustOwnerID(t)
	validPayload := mustPayload(t, []byte("ciphertext"))

	tests := []struct {
		name    string
		id      SecretID
		owner   vo.UserID
		stype   SecretType
		payload Payload
		wantErr error
	}{
		{name: "valid", id: validID, owner: validOwner, stype: SecretTypeCard, payload: validPayload},
		{name: "zero id", id: SecretID{}, owner: validOwner, stype: SecretTypeCard, payload: validPayload, wantErr: ErrInvalidSecretID},
		{name: "zero owner", id: validID, owner: vo.UserID{}, stype: SecretTypeCard, payload: validPayload, wantErr: vo.ErrInvalidUserID},
		{name: "invalid type", id: validID, owner: validOwner, stype: SecretType("totp"), payload: validPayload, wantErr: ErrUnknownSecretType},
		{name: "empty payload", id: validID, owner: validOwner, stype: SecretTypeCard, payload: Payload{}, wantErr: ErrEmptyPayload},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewSecret(tt.id, tt.owner, tt.stype, tt.payload, Metadata{}, now)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewSecret error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewSecret unexpected error: %v", err)
			}

			if got.Version() != 1 {
				t.Fatalf("Version() = %d, want 1", got.Version())
			}

			if got.IsDeleted() {
				t.Fatal("IsDeleted() = true, want false")
			}

			if !got.CreatedAt().Equal(now) || !got.UpdatedAt().Equal(now) {
				t.Fatalf("timestamps = %v/%v, want %v", got.CreatedAt(), got.UpdatedAt(), now)
			}
		})
	}
}

func TestSecretUpdate(t *testing.T) {
	// Arrange
	created := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	updated := created.Add(time.Hour)
	newPayload := []byte("v2")

	tests := []struct {
		name            string
		expectedVersion int64
		payload         Payload
		deleted         bool
		wantErr         error
	}{
		{name: "valid update", expectedVersion: 1, payload: Payload{data: newPayload}},
		{name: "version conflict", expectedVersion: 2, payload: Payload{data: newPayload}, wantErr: ErrVersionConflict},
		{name: "empty payload", expectedVersion: 1, payload: Payload{}, wantErr: ErrEmptyPayload},
		{name: "deleted secret", expectedVersion: 2, payload: Payload{data: newPayload}, deleted: true, wantErr: ErrSecretDeleted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mustSecret(t, created)
			if tt.deleted {
				deleted, err := s.Delete(1, created)
				if err != nil {
					t.Fatalf("Delete: %v", err)
				}
				s = deleted
			}
			versionBefore := s.Version()

			// Act
			got, err := s.Update(tt.payload, Metadata{}, tt.expectedVersion, updated)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Update error = %v, want %v", err, tt.wantErr)
				}
				if got.Version() != versionBefore {
					t.Fatalf("failed Update changed version: %d -> %d", versionBefore, got.Version())
				}
				return
			}

			if err != nil {
				t.Fatalf("Update unexpected error: %v", err)
			}

			if s.Version() != versionBefore {
				t.Fatalf("Update mutated receiver: version %d -> %d", versionBefore, s.Version())
			}

			if got.Version() != versionBefore+1 {
				t.Fatalf("Version() = %d, want %d", got.Version(), versionBefore+1)
			}

			if string(got.Payload().Bytes()) != string(newPayload) {
				t.Fatalf("Payload() = %q, want %q", got.Payload().Bytes(), newPayload)
			}

			if !got.UpdatedAt().Equal(updated) {
				t.Fatalf("UpdatedAt() = %v, want %v", got.UpdatedAt(), updated)
			}

			if !got.CreatedAt().Equal(created) {
				t.Fatalf("CreatedAt() changed: %v", got.CreatedAt())
			}
		})
	}
}

func TestSecretDelete(t *testing.T) {
	// Arrange
	created := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	deletedAt := created.Add(time.Hour)
	s := mustSecret(t, created)

	// Act
	got, err := s.Delete(1, deletedAt)

	// Assert
	if err != nil {
		t.Fatalf("Delete unexpected error: %v", err)
	}

	if s.IsDeleted() {
		t.Fatal("Delete mutated receiver")
	}

	if !got.IsDeleted() {
		t.Fatal("IsDeleted() = false, want true")
	}

	if got.Version() != 2 {
		t.Fatalf("Version() = %d, want 2", got.Version())
	}

	if !got.Payload().IsZero() || !got.Metadata().IsZero() {
		t.Fatal("Delete must wipe payload and metadata")
	}

	if !got.UpdatedAt().Equal(deletedAt) {
		t.Fatalf("UpdatedAt() = %v, want %v", got.UpdatedAt(), deletedAt)
	}
}

func TestSecretDeleteIdempotent(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	s := mustSecret(t, now)
	deleted, err := s.Delete(1, now)
	if err != nil {
		t.Fatalf("first Delete: %v", err)
	}

	// Act
	got, err := deleted.Delete(99, now.Add(time.Hour))

	// Assert
	if err != nil {
		t.Fatalf("repeated Delete error = %v, want nil", err)
	}

	if got.Version() != 2 {
		t.Fatalf("repeated Delete changed version: %d", got.Version())
	}
}

func TestSecretDeleteVersionConflict(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	s := mustSecret(t, now)

	// Act
	got, err := s.Delete(5, now)

	// Assert
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("Delete error = %v, want ErrVersionConflict", err)
	}

	if got.IsDeleted() {
		t.Fatal("failed Delete marked secret deleted")
	}
}
