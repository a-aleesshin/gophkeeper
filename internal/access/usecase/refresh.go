package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
)

type RefreshTokenProvider interface {
	ByID(ctx context.Context, id domain.TokenID) (domain.RefreshToken, error)
}

type RefreshTokenDeleter interface {
	DeleteByID(ctx context.Context, id domain.TokenID) error
}

type TxRunner interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type RefreshCommand struct {
	RefreshToken string
}

type RefreshHandler struct {
	provider   RefreshTokenProvider
	deleter    RefreshTokenDeleter
	issuer     AccessTokenIssuer
	codec      RefreshTokenCodec
	tokens     RefreshTokenCreator
	tx         TxRunner
	clock      clock.Clock
	ids        idgen.Generator
	refreshTTL time.Duration
}

func NewRefreshHandler(
	provider RefreshTokenProvider,
	deleter RefreshTokenDeleter,
	issuer AccessTokenIssuer,
	codec RefreshTokenCodec,
	tokens RefreshTokenCreator,
	tx TxRunner,
	clk clock.Clock,
	ids idgen.Generator,
	refreshTTL time.Duration,
) RefreshHandler {
	return RefreshHandler{
		provider:   provider,
		deleter:    deleter,
		issuer:     issuer,
		codec:      codec,
		tokens:     tokens,
		tx:         tx,
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

	var result LoginResult
	err = h.tx.InTx(ctx, func(ctx context.Context) error {
		stored, err := h.provider.ByID(ctx, tokenID)
		if err != nil {
			return fmt.Errorf("find refresh token: %w", err)
		}
		if !stored.Hash().Equal(hash) {
			return domain.ErrRefreshTokenNotFound
		}

		now := h.clock.Now()
		if stored.IsExpired(now) {
			if err := h.deleter.DeleteByID(ctx, stored.ID()); err != nil {
				return fmt.Errorf("delete expired token: %w", err)
			}
			return domain.ErrRefreshTokenExpired
		}

		if err := h.deleter.DeleteByID(ctx, stored.ID()); err != nil {
			return fmt.Errorf("rotate token: %w", err)
		}

		result, err = issueTokens(ctx, issueDeps{
			issuer: h.issuer,
			codec:  h.codec,
			tokens: h.tokens,
			ids:    h.ids,
		}, stored.UserID(), now, h.refreshTTL)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	return result, nil
}
