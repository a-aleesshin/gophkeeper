package usecase

import (
	"context"
	"fmt"
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type SecretProvider interface {
	Get(ctx context.Context, ownerID vo.UserID, id domain.SecretID) (domain.Secret, error)
}

type GetSecretQuery struct {
	OwnerID  vo.UserID
	SecretID string
}

type GetSecretResult struct {
	SecretID  string
	Type      string
	Payload   []byte
	Metadata  []byte
	Version   int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

type GetSecretHandler struct {
	secrets SecretProvider
}

func NewGetSecretHandler(secrets SecretProvider) GetSecretHandler {
	return GetSecretHandler{secrets: secrets}
}

func (h GetSecretHandler) Handle(ctx context.Context, query GetSecretQuery) (GetSecretResult, error) {
	if query.OwnerID.IsZero() {
		return GetSecretResult{}, vo.ErrInvalidUserID
	}

	id, err := domain.ParseSecretID(query.SecretID)
	if err != nil {
		return GetSecretResult{}, err
	}

	secret, err := h.secrets.Get(ctx, query.OwnerID, id)
	if err != nil {
		return GetSecretResult{}, fmt.Errorf("get secret %s: %w", id, err)
	}
	
	if secret.IsDeleted() {
		return GetSecretResult{}, domain.ErrSecretNotFound
	}

	return GetSecretResult{
		SecretID:  secret.ID().String(),
		Type:      secret.Type().String(),
		Payload:   secret.Payload().Bytes(),
		Metadata:  secret.Metadata().Bytes(),
		Version:   secret.Version(),
		CreatedAt: secret.CreatedAt(),
		UpdatedAt: secret.UpdatedAt(),
	}, nil
}
