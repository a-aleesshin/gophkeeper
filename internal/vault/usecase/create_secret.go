package usecase

import (
	"context"
	"fmt"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type SecretCreator interface {
	Create(ctx context.Context, secret domain.Secret) error
}

type CreateSecretCommand struct {
	OwnerID  vo.UserID
	SecretID string
	Type     string
	Payload  []byte
	Metadata []byte
}

type CreateSecretResult struct {
	Version int64
}

type CreateSecretHandler struct {
	secrets SecretCreator
	clock   clock.Clock
}

func NewCreateSecretHandler(secrets SecretCreator, clk clock.Clock) CreateSecretHandler {
	return CreateSecretHandler{secrets: secrets, clock: clk}
}

func (h CreateSecretHandler) Handle(ctx context.Context, cmd CreateSecretCommand) (CreateSecretResult, error) {
	id, err := domain.ParseSecretID(cmd.SecretID)
	if err != nil {
		return CreateSecretResult{}, err
	}

	secretType, err := domain.ParseSecretType(cmd.Type)
	if err != nil {
		return CreateSecretResult{}, err
	}

	payload, err := domain.NewPayload(cmd.Payload)
	if err != nil {
		return CreateSecretResult{}, err
	}
	
	metadata, err := domain.NewMetadata(cmd.Metadata)
	if err != nil {
		return CreateSecretResult{}, err
	}

	secret, err := domain.NewSecret(id, cmd.OwnerID, secretType, payload, metadata, h.clock.Now())
	if err != nil {
		return CreateSecretResult{}, err
	}

	if err := h.secrets.Create(ctx, secret); err != nil {
		return CreateSecretResult{}, fmt.Errorf("create secret %s: %w", id, err)
	}

	return CreateSecretResult{Version: secret.Version()}, nil
}
