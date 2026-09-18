package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type fakeSecretCreator struct {
	created []domain.Secret
	err     error
}

func (f *fakeSecretCreator) Create(_ context.Context, secret domain.Secret) error {
	if f.err != nil {
		return f.err
	}
	f.created = append(f.created, secret)
	return nil
}

type fakeSecretProvider struct {
	secret domain.Secret
	err    error
}

func (f *fakeSecretProvider) Get(_ context.Context, _ vo.UserID, _ domain.SecretID) (domain.Secret, error) {
	return f.secret, f.err
}

type fakeSecretLister struct {
	items []SecretHeader
	err   error
}

func (f *fakeSecretLister) ListByOwner(_ context.Context, _ vo.UserID) ([]SecretHeader, error) {
	return f.items, f.err
}

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time { return f.now }

func mustOwnerID(t *testing.T) vo.UserID {
	t.Helper()

	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}

	return id
}

func mustSecret(t *testing.T, ownerID vo.UserID, now time.Time) domain.Secret {
	t.Helper()

	id, err := domain.SecretIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("SecretIDFromUUID: %v", err)
	}

	payload, err := domain.NewPayload([]byte("ciphertext"))
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}

	metadata, err := domain.NewMetadata([]byte("encrypted-meta"))
	if err != nil {
		t.Fatalf("NewMetadata: %v", err)
	}

	secret, err := domain.NewSecret(id, ownerID, domain.SecretTypeCredentials, payload, metadata, now)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	
	return secret
}
