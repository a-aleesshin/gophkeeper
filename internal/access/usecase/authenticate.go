package usecase

import (
	"context"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type AccessTokenVerifier interface {
	Verify(ctx context.Context, token string) (vo.UserID, error)
}

type AuthenticateCommand struct {
	AccessToken string
}

type AuthenticateResult struct {
	UserID vo.UserID
}

type AuthenticateHandler struct {
	verifier AccessTokenVerifier
}

func NewAuthenticateHandler(verifier AccessTokenVerifier) AuthenticateHandler {
	return AuthenticateHandler{verifier: verifier}
}

func (h AuthenticateHandler) Handle(ctx context.Context, cmd AuthenticateCommand) (AuthenticateResult, error) {
	userID, err := h.verifier.Verify(ctx, cmd.AccessToken)
	if err != nil {
		return AuthenticateResult{}, err
	}

	return AuthenticateResult{UserID: userID}, nil
}
