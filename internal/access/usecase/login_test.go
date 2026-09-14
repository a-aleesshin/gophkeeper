package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
)

func TestLoginHandler(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	accessExp := now.Add(15 * time.Minute)
	refreshTTL := 30 * 24 * time.Hour
	userID := mustUserID(t)
	issuerErr := errors.New("signing failed")
	storeErr := errors.New("connection refused")

	tests := []struct {
		name     string
		verifier *fakeVerifier
		issuer   *fakeIssuer
		store    *fakeTokenStore
		wantErr  error
	}{
		{
			name:     "success",
			verifier: &fakeVerifier{userID: userID},
			issuer:   &fakeIssuer{token: "jwt-token", expiresAt: accessExp},
			store:    newFakeTokenStore(),
		},
		{
			name:     "invalid credentials",
			verifier: &fakeVerifier{err: domain.ErrInvalidCredentials},
			issuer:   &fakeIssuer{token: "jwt-token", expiresAt: accessExp},
			store:    newFakeTokenStore(),
			wantErr:  domain.ErrInvalidCredentials,
		},
		{
			name:     "issuer failure",
			verifier: &fakeVerifier{userID: userID},
			issuer:   &fakeIssuer{err: issuerErr},
			store:    newFakeTokenStore(),
			wantErr:  issuerErr,
		},
		{
			name:     "store failure",
			verifier: &fakeVerifier{userID: userID},
			issuer:   &fakeIssuer{token: "jwt-token", expiresAt: accessExp},
			store:    &fakeTokenStore{tokens: map[string]domain.RefreshToken{}, createErr: storeErr},
			wantErr:  storeErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewLoginHandler(tt.verifier, tt.issuer, &fakeCodec{}, tt.store, fixedClock{now: now}, fakeIDGen{}, refreshTTL)

			// Act
			got, err := h.Handle(context.Background(), LoginCommand{Login: "alice", Password: "correct horse battery"})

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Handle error = %v, want %v", err, tt.wantErr)
				}
				if len(tt.store.tokens) != 0 {
					t.Fatal("refresh token must not be stored on failure")
				}
				return
			}

			if err != nil {
				t.Fatalf("Handle unexpected error: %v", err)
			}

			if got.AccessToken != "jwt-token" || !got.AccessExpiresAt.Equal(accessExp) {
				t.Fatalf("access = %q/%v", got.AccessToken, got.AccessExpiresAt)
			}

			if got.RefreshToken == "" {
				t.Fatal("empty refresh token")
			}

			if !got.RefreshExpiresAt.Equal(now.Add(refreshTTL)) {
				t.Fatalf("RefreshExpiresAt = %v, want %v", got.RefreshExpiresAt, now.Add(refreshTTL))
			}

			if len(tt.store.tokens) != 1 {
				t.Fatalf("stored tokens = %d, want 1", len(tt.store.tokens))
			}

			tokenID, tokenHash, err := (&fakeCodec{}).Parse(got.RefreshToken)
			if err != nil {
				t.Fatalf("Parse issued token: %v", err)
			}
			stored, ok := tt.store.tokens[tokenID.String()]
			if !ok {
				t.Fatal("issued token id is not in store")
			}
			if stored.UserID() != userID {
				t.Fatalf("stored userID = %v, want %v", stored.UserID(), userID)
			}
			if !stored.Hash().Equal(tokenHash) {
				t.Fatal("stored hash does not match issued token")
			}
		})
	}
}
