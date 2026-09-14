package usecase

import (
	"context"
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type fakeStore struct {
	secrets map[string]domain.Secret
}

func newFakeStore() *fakeStore {
	return &fakeStore{secrets: make(map[string]domain.Secret)}
}

func (f *fakeStore) Get(_ context.Context, ownerID vo.UserID, id domain.SecretID) (domain.Secret, error) {
	s, ok := f.secrets[id.String()]
	if !ok || s.OwnerID() != ownerID {
		return domain.Secret{}, domain.ErrSecretNotFound
	}
	return s, nil
}

func (f *fakeStore) Create(_ context.Context, secret domain.Secret) error {
	if _, ok := f.secrets[secret.ID().String()]; ok {
		return domain.ErrSecretAlreadyExists
	}
	f.secrets[secret.ID().String()] = secret
	return nil
}

func (f *fakeStore) Save(_ context.Context, secret domain.Secret) error {
	f.secrets[secret.ID().String()] = secret
	return nil
}

func (f *fakeStore) ListChangedSince(_ context.Context, ownerID vo.UserID, since time.Time) ([]domain.Secret, error) {
	var out []domain.Secret
	for _, s := range f.secrets {
		if s.OwnerID() == ownerID && s.UpdatedAt().After(since) {
			out = append(out, s)
		}
	}
	return out, nil
}

type fakeTxRunner struct {
	calls int
}

func (f *fakeTxRunner) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	f.calls++
	return fn(ctx)
}
