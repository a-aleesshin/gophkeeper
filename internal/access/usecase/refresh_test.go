package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
)

func TestRefreshHandlerRotatesToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	refreshTTL := 30 * 24 * time.Hour
	userID := mustUserID(t)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	old, oldPlaintext := storeToken(t, store, codec, userID, "old-secret", now.Add(-time.Hour), refreshTTL)
	issuer := &fakeIssuer{token: "new-jwt", expiresAt: now.Add(15 * time.Minute)}
	h := NewRefreshHandler(store, issuer, codec, store, fixedClock{now: now}, fakeIDGen{}, refreshTTL)

	// Act
	got, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: oldPlaintext})

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got.AccessToken != "new-jwt" {
		t.Fatalf("AccessToken = %q", got.AccessToken)
	}
	if got.RefreshToken == "" || got.RefreshToken == oldPlaintext {
		t.Fatalf("RefreshToken = %q, want new token", got.RefreshToken)
	}
	if _, ok := store.tokens[old.ID().String()]; ok {
		t.Fatal("old token must be deleted after rotation")
	}
	if len(store.tokens) != 1 {
		t.Fatalf("stored tokens = %d, want 1", len(store.tokens))
	}
	newID, newHash, err := codec.Parse(got.RefreshToken)
	if err != nil {
		t.Fatalf("Parse new token: %v", err)
	}
	stored, ok := store.tokens[newID.String()]
	if !ok {
		t.Fatal("returned token id is not in store")
	}
	if !stored.Hash().Equal(newHash) {
		t.Fatal("stored hash does not match returned token")
	}
	if stored.UserID() != userID {
		t.Fatalf("rotated token userID = %v, want %v", stored.UserID(), userID)
	}
}

func TestRefreshHandlerSingleUse(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	_, plaintext := storeToken(t, store, codec, mustUserID(t), "one-shot", now, time.Hour)
	issuer := &fakeIssuer{token: "jwt", expiresAt: now.Add(15 * time.Minute)}
	h := NewRefreshHandler(store, issuer, codec, store, fixedClock{now: now}, fakeIDGen{}, time.Hour)

	// Act
	if _, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: plaintext}); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	_, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: plaintext})

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("second Handle error = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshHandlerUnknownToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	h := NewRefreshHandler(store, &fakeIssuer{}, codec, store, fixedClock{now: now}, fakeIDGen{}, time.Hour)
	ghost := uuid.Must(uuid.NewV7()).String() + ".some-secret"

	// Act
	_, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: ghost})

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("Handle error = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshHandlerWrongSecret(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	token, _ := storeToken(t, store, codec, mustUserID(t), "real-secret", now, time.Hour)
	h := NewRefreshHandler(store, &fakeIssuer{}, codec, store, fixedClock{now: now}, fakeIDGen{}, time.Hour)

	// Act
	_, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: token.ID().String() + ".stolen-guess"})

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("Handle error = %v, want ErrRefreshTokenNotFound", err)
	}
	if _, ok := store.tokens[token.ID().String()]; !ok {
		t.Fatal("token must not be deleted on wrong secret")
	}
}

func TestRefreshHandlerExpiredToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	expired, plaintext := storeToken(t, store, codec, mustUserID(t), "expired-secret", now.Add(-2*time.Hour), time.Hour)
	h := NewRefreshHandler(store, &fakeIssuer{}, codec, store, fixedClock{now: now}, fakeIDGen{}, time.Hour)

	// Act
	_, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: plaintext})

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenExpired) {
		t.Fatalf("Handle error = %v, want ErrRefreshTokenExpired", err)
	}
	if _, ok := store.tokens[expired.ID().String()]; ok {
		t.Fatal("expired token must be consumed")
	}
}

func TestRefreshHandlerMalformedToken(t *testing.T) {
	// Arrange
	store := newFakeTokenStore()
	h := NewRefreshHandler(store, &fakeIssuer{}, &fakeCodec{}, store, fixedClock{}, fakeIDGen{}, time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "no separator", token: "justonepart"},
		{name: "bad uuid", token: "not-a-uuid.secret"},
		{name: "empty secret", token: uuid.Must(uuid.NewV7()).String() + "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			_, err := h.Handle(context.Background(), RefreshCommand{RefreshToken: tt.token})

			// Assert
			if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
				t.Fatalf("Handle error = %v, want ErrRefreshTokenNotFound", err)
			}
		})
	}
}
