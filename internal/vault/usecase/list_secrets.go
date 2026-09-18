package usecase

import (
	"context"
	"fmt"
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type SecretHeader struct {
	SecretID  string
	Type      string
	Metadata  []byte
	Version   int64
	UpdatedAt time.Time
}

type SecretLister interface {
	ListByOwner(ctx context.Context, ownerID vo.UserID) ([]SecretHeader, error)
}

type ListSecretsQuery struct {
	OwnerID vo.UserID
}

type ListSecretsResult struct {
	Items []SecretHeader
}

type ListSecretsHandler struct {
	secrets SecretLister
}

func NewListSecretsHandler(secrets SecretLister) ListSecretsHandler {
	return ListSecretsHandler{secrets: secrets}
}

func (h ListSecretsHandler) Handle(ctx context.Context, query ListSecretsQuery) (ListSecretsResult, error) {
	if query.OwnerID.IsZero() {
		return ListSecretsResult{}, vo.ErrInvalidUserID
	}

	items, err := h.secrets.ListByOwner(ctx, query.OwnerID)
	if err != nil {
		return ListSecretsResult{}, fmt.Errorf("list secrets: %w", err)
	}

	return ListSecretsResult{Items: items}, nil
}
