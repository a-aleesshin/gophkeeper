package usecase

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
)

type fakeUserCreator struct {
	created []domain.User
	err     error
}

func (f *fakeUserCreator) Create(_ context.Context, user domain.User) error {
	if f.err != nil {
		return f.err
	}
	f.created = append(f.created, user)
	return nil
}

type fakeHasher struct {
	hash domain.PasswordHash
	err  error
}

func (f *fakeHasher) Hash(_ context.Context, _ domain.Password) (domain.PasswordHash, error) {
	return f.hash, f.err
}

type fakeUserProvider struct {
	user domain.User
	err  error
}

func (f *fakeUserProvider) ByLogin(_ context.Context, _ domain.Login) (domain.User, error) {
	return f.user, f.err
}

type fakeVerifier struct {
	ok       bool
	err      error
	compared []domain.PasswordHash
}

func (f *fakeVerifier) Compare(_ context.Context, hash domain.PasswordHash, _ domain.Password) (bool, error) {
	f.compared = append(f.compared, hash)
	return f.ok, f.err
}

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time { return f.now }

type fakeIDGen struct {
	id  uuid.UUID
	err error
}

func (f fakeIDGen) NewID() (uuid.UUID, error) { return f.id, f.err }
