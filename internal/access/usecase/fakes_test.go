package usecase

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type fakeVerifier struct {
	userID vo.UserID
	err    error
}

func (f *fakeVerifier) VerifyCredentials(_ context.Context, _, _ string) (vo.UserID, error) {
	return f.userID, f.err
}

type fakeIssuer struct {
	token     string
	expiresAt time.Time
	err       error
}

func (f *fakeIssuer) Issue(_ context.Context, _ vo.UserID, _ time.Time) (string, time.Time, error) {
	return f.token, f.expiresAt, f.err
}

type fakeCodec struct {
	err error
}

func (f *fakeCodec) New(id domain.TokenID) (string, domain.TokenHash, error) {
	if f.err != nil {
		return "", domain.TokenHash{}, f.err
	}
	secret := "secret-" + id.String()[:8]
	return id.String() + "." + secret, fakeHash(secret), nil
}

func (f *fakeCodec) Parse(plaintext string) (domain.TokenID, domain.TokenHash, error) {
	idPart, secret, ok := strings.Cut(plaintext, ".")
	if !ok || secret == "" {
		return domain.TokenID{}, domain.TokenHash{}, domain.ErrRefreshTokenNotFound
	}
	raw, err := uuid.Parse(idPart)
	if err != nil {
		return domain.TokenID{}, domain.TokenHash{}, domain.ErrRefreshTokenNotFound
	}
	id, err := domain.TokenIDFromUUID(raw)
	if err != nil {
		return domain.TokenID{}, domain.TokenHash{}, domain.ErrRefreshTokenNotFound
	}
	return id, fakeHash(secret), nil
}

func fakeHash(secret string) domain.TokenHash {
	h, err := domain.NewTokenHash([]byte("hash-" + secret))
	if err != nil {
		panic(err)
	}
	return h
}

type fakeTokenStore struct {
	tokens    map[string]domain.RefreshToken
	createErr error
}

func newFakeTokenStore() *fakeTokenStore {
	return &fakeTokenStore{tokens: make(map[string]domain.RefreshToken)}
}

func (f *fakeTokenStore) Create(_ context.Context, token domain.RefreshToken) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.tokens[token.ID().String()] = token
	return nil
}

func (f *fakeTokenStore) ByID(_ context.Context, id domain.TokenID) (domain.RefreshToken, error) {
	t, ok := f.tokens[id.String()]
	if !ok {
		return domain.RefreshToken{}, domain.ErrRefreshTokenNotFound
	}
	return t, nil
}

func (f *fakeTokenStore) DeleteByID(_ context.Context, id domain.TokenID) error {
	delete(f.tokens, id.String())
	return nil
}

type fakeTxRunner struct {
	calls int
}

func (f *fakeTxRunner) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	f.calls++
	return fn(ctx)
}

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time { return f.now }

type fakeIDGen struct {
	err error
}

func (f fakeIDGen) NewID() (uuid.UUID, error) {
	if f.err != nil {
		return uuid.Nil, f.err
	}
	return uuid.NewV7()
}

func mustUserID(t *testing.T) vo.UserID {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return id
}

func storeToken(t *testing.T, store *fakeTokenStore, codec *fakeCodec, userID vo.UserID, secret string, now time.Time, ttl time.Duration) (domain.RefreshToken, string) {
	t.Helper()
	id, err := domain.TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("TokenIDFromUUID: %v", err)
	}
	plaintext := id.String() + "." + secret
	_, hash, err := codec.Parse(plaintext)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	token, err := domain.NewRefreshToken(id, userID, hash, now, ttl)
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	if err := store.Create(context.Background(), token); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return token, plaintext
}
