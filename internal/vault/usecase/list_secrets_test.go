package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

func TestListSecretsHandler(t *testing.T) {
	// Arrange
	owner := mustOwnerID(t)
	storageErr := errors.New("connection refused")
	items := []SecretHeader{
		{
			SecretID:  uuid.Must(uuid.NewV7()).String(),
			Type:      "credentials",
			Metadata:  []byte("encrypted-meta"),
			Version:   3,
			UpdatedAt: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
		},
		{
			SecretID:  uuid.Must(uuid.NewV7()).String(),
			Type:      "card",
			Version:   1,
			UpdatedAt: time.Date(2026, 9, 14, 13, 0, 0, 0, time.UTC),
		},
	}

	tests := []struct {
		name      string
		query     ListSecretsQuery
		lister    *fakeSecretLister
		wantErr   error
		wantItems int
	}{
		{name: "success", query: ListSecretsQuery{OwnerID: owner}, lister: &fakeSecretLister{items: items}, wantItems: 2},
		{name: "empty list", query: ListSecretsQuery{OwnerID: owner}, lister: &fakeSecretLister{}, wantItems: 0},
		{name: "zero owner", query: ListSecretsQuery{}, lister: &fakeSecretLister{items: items}, wantErr: vo.ErrInvalidUserID},
		{name: "storage failure", query: ListSecretsQuery{OwnerID: owner}, lister: &fakeSecretLister{err: storageErr}, wantErr: storageErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewListSecretsHandler(tt.lister)

			// Act
			got, err := h.Handle(context.Background(), tt.query)

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

			if len(got.Items) != tt.wantItems {
				t.Fatalf("items = %d, want %d", len(got.Items), tt.wantItems)
			}

			if tt.wantItems > 0 && got.Items[0].SecretID != items[0].SecretID {
				t.Fatalf("Items[0].SecretID = %s, want %s", got.Items[0].SecretID, items[0].SecretID)
			}
		})
	}
}
