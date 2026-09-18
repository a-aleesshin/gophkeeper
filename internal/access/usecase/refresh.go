package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
)

type RefreshTokenConsumer interface {
	Consume(ctx context.Context, id domain.TokenID, hash domain.TokenHash) (domain.RefreshToken, error)
}

type RefreshCommand struct {
	RefreshToken string
}

type RefreshHandler struct {
	consumer   RefreshTokenConsumer
	issuer     AccessTokenIssuer
	codec      RefreshTokenCodec
	tokens     RefreshTokenCreator
	clock      clock.Clock
	ids        idgen.Generator
	refreshTTL time.Duration
}

func NewRefreshHandler(
	consumer RefreshTokenConsumer,
	issuer AccessTokenIssuer,
	codec RefreshTokenCodec,
	tokens RefreshTokenCreator,
	clk clock.Clock,
	ids idgen.Generator,
	refreshTTL time.Duration,
) RefreshHandler {
	return RefreshHandler{
		consumer:   consumer,
		issuer:     issuer,
		codec:      codec,
		tokens:     tokens,
		clock:      clk,
		ids:        ids,
		refreshTTL: refreshTTL,
	}
}

func (h RefreshHandler) Handle(ctx context.Context, cmd RefreshCommand) (LoginResult, error) {
	tokenID, hash, err := h.codec.Parse(cmd.RefreshToken)
	if err != nil {
		return LoginResult{}, err
	}

	stored, err := h.consumer.Consume(ctx, tokenID, hash)
	if err != nil {
		return LoginResult{}, fmt.Errorf("consume refresh token: %w", err)
	}

	now := h.clock.Now()
	if stored.IsExpired(now) {
		return LoginResult{}, domain.ErrRefreshTokenExpired
	}

	return issueTokens(ctx, issueDeps{
		issuer: h.issuer,
		codec:  h.codec,
		tokens: h.tokens,
		ids:    h.ids,
	}, stored.UserID(), now, h.refreshTTL)
}
