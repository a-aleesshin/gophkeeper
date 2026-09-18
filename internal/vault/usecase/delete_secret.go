package usecase

import (
	"context"
	"fmt"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type DeleteSecretCommand struct {
	OwnerID  vo.UserID
	SecretID string
	Version  int64
}

type DeleteSecretResult struct {
	Version int64
}

type DeleteSecretHandler struct {
	provider SecretProvider
	saver    SecretSaver
	clock    clock.Clock
}

func NewDeleteSecretHandler(provider SecretProvider, saver SecretSaver, clk clock.Clock) DeleteSecretHandler {
	return DeleteSecretHandler{provider: provider, saver: saver, clock: clk}
}

func (h DeleteSecretHandler) Handle(ctx context.Context, cmd DeleteSecretCommand) (DeleteSecretResult, error) {
	if cmd.OwnerID.IsZero() {
		return DeleteSecretResult{}, vo.ErrInvalidUserID
	}
	id, err := domain.ParseSecretID(cmd.SecretID)
	if err != nil {
		return DeleteSecretResult{}, err
	}

	secret, err := h.provider.Get(ctx, cmd.OwnerID, id)
	if err != nil {
		return DeleteSecretResult{}, fmt.Errorf("get secret %s: %w", id, err)
	}
	if secret.IsDeleted() {
		return DeleteSecretResult{Version: secret.Version()}, nil
	}

	deleted, err := secret.Delete(cmd.Version, h.clock.Now())
	if err != nil {
		return DeleteSecretResult{}, err
	}

	if err := h.saver.Save(ctx, deleted); err != nil {
		return DeleteSecretResult{}, fmt.Errorf("save secret %s: %w", id, err)
	}

	return DeleteSecretResult{Version: deleted.Version()}, nil
}
