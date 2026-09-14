package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
)

type LogoutCommand struct {
	RefreshToken string
}

type LogoutHandler struct {
	provider RefreshTokenProvider
	deleter  RefreshTokenDeleter
	codec    RefreshTokenCodec
}

func NewLogoutHandler(provider RefreshTokenProvider, deleter RefreshTokenDeleter, codec RefreshTokenCodec) LogoutHandler {
	return LogoutHandler{provider: provider, deleter: deleter, codec: codec}
}

func (h LogoutHandler) Handle(ctx context.Context, cmd LogoutCommand) error {
	tokenID, hash, err := h.codec.Parse(cmd.RefreshToken)
	if err != nil {
		return nil
	}

	stored, err := h.provider.ByID(ctx, tokenID)
	if err != nil {
		if errors.Is(err, domain.ErrRefreshTokenNotFound) {
			return nil
		}
		return fmt.Errorf("find refresh token: %w", err)
	}
	if !stored.Hash().Equal(hash) {
		return nil
	}

	if err := h.deleter.DeleteByID(ctx, stored.ID()); err != nil {
		return fmt.Errorf("delete refresh token: %w", err)
	}
	return nil
}
