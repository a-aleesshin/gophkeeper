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
	consumer RefreshTokenConsumer
	codec    RefreshTokenCodec
}

func NewLogoutHandler(consumer RefreshTokenConsumer, codec RefreshTokenCodec) LogoutHandler {
	return LogoutHandler{consumer: consumer, codec: codec}
}

func (h LogoutHandler) Handle(ctx context.Context, cmd LogoutCommand) error {
	tokenID, hash, err := h.codec.Parse(cmd.RefreshToken)
	if err != nil {
		return nil
	}

	if _, err := h.consumer.Consume(ctx, tokenID, hash); err != nil {
		if errors.Is(err, domain.ErrRefreshTokenNotFound) {
			return nil
		}
		return fmt.Errorf("consume refresh token: %w", err)
	}
	return nil
}
