package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
)

type CredentialsVerifier interface {
	VerifyCredentials(ctx context.Context, login, password string) (vo.UserID, error)
}

type AccessTokenIssuer interface {
	Issue(ctx context.Context, userID vo.UserID, now time.Time) (token string, expiresAt time.Time, err error)
}

type RefreshTokenCodec interface {
	New(id domain.TokenID) (plaintext string, hash domain.TokenHash, err error)
	Parse(plaintext string) (domain.TokenID, domain.TokenHash, error)
}

type RefreshTokenCreator interface {
	Create(ctx context.Context, token domain.RefreshToken) error
}

type LoginCommand struct {
	Login    string
	Password string
}

type LoginResult struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

type LoginHandler struct {
	verifier   CredentialsVerifier
	issuer     AccessTokenIssuer
	codec      RefreshTokenCodec
	tokens     RefreshTokenCreator
	clock      clock.Clock
	ids        idgen.Generator
	refreshTTL time.Duration
}

func NewLoginHandler(
	verifier CredentialsVerifier,
	issuer AccessTokenIssuer,
	codec RefreshTokenCodec,
	tokens RefreshTokenCreator,
	clk clock.Clock,
	ids idgen.Generator,
	refreshTTL time.Duration,
) LoginHandler {
	return LoginHandler{
		verifier:   verifier,
		issuer:     issuer,
		codec:      codec,
		tokens:     tokens,
		clock:      clk,
		ids:        ids,
		refreshTTL: refreshTTL,
	}
}

func (h LoginHandler) Handle(ctx context.Context, cmd LoginCommand) (LoginResult, error) {
	userID, err := h.verifier.VerifyCredentials(ctx, cmd.Login, cmd.Password)
	if err != nil {
		return LoginResult{}, err
	}

	return issueTokens(ctx, issueDeps{
		issuer: h.issuer,
		codec:  h.codec,
		tokens: h.tokens,
		ids:    h.ids,
	}, userID, h.clock.Now(), h.refreshTTL)
}

type issueDeps struct {
	issuer AccessTokenIssuer
	codec  RefreshTokenCodec
	tokens RefreshTokenCreator
	ids    idgen.Generator
}

func issueTokens(ctx context.Context, deps issueDeps, userID vo.UserID, now time.Time, refreshTTL time.Duration) (LoginResult, error) {
	accessToken, accessExpiresAt, err := deps.issuer.Issue(ctx, userID, now)
	if err != nil {
		return LoginResult{}, fmt.Errorf("issue access token: %w", err)
	}

	rawID, err := deps.ids.NewID()
	if err != nil {
		return LoginResult{}, fmt.Errorf("generate token id: %w", err)
	}

	tokenID, err := domain.TokenIDFromUUID(rawID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("generate token id: %w", err)
	}

	plaintext, hash, err := deps.codec.New(tokenID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshToken, err := domain.NewRefreshToken(tokenID, userID, hash, now, refreshTTL)
	if err != nil {
		return LoginResult{}, err
	}
	if err := deps.tokens.Create(ctx, refreshToken); err != nil {
		return LoginResult{}, fmt.Errorf("store refresh token: %w", err)
	}

	return LoginResult{
		AccessToken:      accessToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshToken:     plaintext,
		RefreshExpiresAt: refreshToken.ExpiresAt(),
	}, nil
}
