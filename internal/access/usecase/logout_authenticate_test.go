package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type fakeAccessVerifier struct {
	userID vo.UserID
	err    error
}

func (f *fakeAccessVerifier) Verify(_ context.Context, _ string) (vo.UserID, error) {
	return f.userID, f.err
}

func TestLogoutHandler(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	_, plaintext := storeToken(t, store, codec, mustUserID(t), "active-secret", now, time.Hour)
	h := NewLogoutHandler(store, store, codec)

	// Act
	err := h.Handle(context.Background(), LogoutCommand{RefreshToken: plaintext})

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(store.tokens) != 0 {
		t.Fatal("token must be deleted on logout")
	}
}

func TestLogoutHandlerWrongSecretKeepsToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	store := newFakeTokenStore()
	codec := &fakeCodec{}
	token, _ := storeToken(t, store, codec, mustUserID(t), "real-secret", now, time.Hour)
	h := NewLogoutHandler(store, store, codec)

	// Act
	err := h.Handle(context.Background(), LogoutCommand{RefreshToken: token.ID().String() + ".stolen-guess"})

	// Assert
	if err != nil {
		t.Fatalf("Handle error = %v, want nil", err)
	}
	if len(store.tokens) != 1 {
		t.Fatal("token must not be deleted on wrong secret")
	}
}

func TestLogoutHandlerMalformedTokenIsNoop(t *testing.T) {
	// Arrange
	h := NewLogoutHandler(newFakeTokenStore(), newFakeTokenStore(), &fakeCodec{})

	tests := []string{"", "ghost", "not-a-uuid.secret"}

	for _, token := range tests {
		// Act
		err := h.Handle(context.Background(), LogoutCommand{RefreshToken: token})

		// Assert
		if err != nil {
			t.Fatalf("Handle(%q) error = %v, want nil", token, err)
		}
	}
}

func TestAuthenticateHandler(t *testing.T) {
	// Arrange
	userID := mustUserID(t)
	tests := []struct {
		name     string
		verifier *fakeAccessVerifier
		wantErr  error
	}{
		{name: "success", verifier: &fakeAccessVerifier{userID: userID}},
		{name: "invalid token", verifier: &fakeAccessVerifier{err: domain.ErrInvalidAccessToken}, wantErr: domain.ErrInvalidAccessToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewAuthenticateHandler(tt.verifier)

			// Act
			got, err := h.Handle(context.Background(), AuthenticateCommand{AccessToken: "some-jwt"})

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
			if got.UserID != userID {
				t.Fatalf("UserID = %v, want %v", got.UserID, userID)
			}
		})
	}
}
