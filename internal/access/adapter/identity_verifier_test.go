package adapter

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	identityapi "github.com/a-aleesshin/gophkeeper/internal/identity/api"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type fakeIdentityAPI struct {
	userID vo.UserID
	err    error
}

func (f *fakeIdentityAPI) VerifyCredentials(_ context.Context, _, _ string) (vo.UserID, error) {
	return f.userID, f.err
}

func TestIdentityCredentialsVerifier(t *testing.T) {
	// Arrange
	rawID, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	infraErr := errors.New("connection refused")

	tests := []struct {
		name    string
		api     *fakeIdentityAPI
		wantErr error
		wantID  vo.UserID
	}{
		{name: "success", api: &fakeIdentityAPI{userID: rawID}, wantID: rawID},
		{name: "invalid credentials translated", api: &fakeIdentityAPI{err: identityapi.ErrInvalidCredentials}, wantErr: domain.ErrInvalidCredentials},
		{name: "infrastructure error wrapped", api: &fakeIdentityAPI{err: infraErr}, wantErr: infraErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewIdentityCredentialsVerifier(tt.api)

			// Act
			got, err := verifier.VerifyCredentials(context.Background(), "alice", "correct horse battery")

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("VerifyCredentials error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyCredentials unexpected error: %v", err)
			}
			if got != tt.wantID {
				t.Fatalf("userID = %v, want %v", got, tt.wantID)
			}
		})
	}
}
