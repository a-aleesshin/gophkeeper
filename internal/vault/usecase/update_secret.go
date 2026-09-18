package usecase

import (
	"context"
	"fmt"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type SecretSaver interface {
	Save(ctx context.Context, secret domain.Secret) error
}

type UpdateSecretCommand struct {
	OwnerID  vo.UserID
	SecretID string
	Payload  []byte
	Metadata []byte
	Version  int64
}

type UpdateSecretResult struct {
	Version int64
}

type UpdateSecretHandler struct {
	provider SecretProvider
	saver    SecretSaver
	clock    clock.Clock
}

func NewUpdateSecretHandler(provider SecretProvider, saver SecretSaver, clk clock.Clock) UpdateSecretHandler {
	return UpdateSecretHandler{provider: provider, saver: saver, clock: clk}
}

func (h UpdateSecretHandler) Handle(ctx context.Context, cmd UpdateSecretCommand) (UpdateSecretResult, error) {
	if cmd.OwnerID.IsZero() {
		return UpdateSecretResult{}, vo.ErrInvalidUserID
	}

	id, err := domain.ParseSecretID(cmd.SecretID)
	if err != nil {
		return UpdateSecretResult{}, err
	}

	payload, err := domain.NewPayload(cmd.Payload)
	if err != nil {
		return UpdateSecretResult{}, err
	}

	metadata, err := domain.NewMetadata(cmd.Metadata)
	if err != nil {
		return UpdateSecretResult{}, err
	}

	secret, err := h.provider.Get(ctx, cmd.OwnerID, id)
	if err != nil {
		return UpdateSecretResult{}, fmt.Errorf("get secret %s: %w", id, err)
	}

	updated, err := secret.Update(payload, metadata, cmd.Version, h.clock.Now())
	if err != nil {
		return UpdateSecretResult{}, err
	}

	if err := h.saver.Save(ctx, updated); err != nil {
		return UpdateSecretResult{}, fmt.Errorf("save secret %s: %w", id, err)
	}

	return UpdateSecretResult{Version: updated.Version()}, nil
}
