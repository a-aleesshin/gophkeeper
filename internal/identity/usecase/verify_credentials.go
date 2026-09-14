package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type UserByLoginProvider interface {
	ByLogin(ctx context.Context, login domain.Login) (domain.User, error)
}

type PasswordVerifier interface {
	Compare(ctx context.Context, hash domain.PasswordHash, password domain.Password) (bool, error)
}

type VerifyCredentialsCommand struct {
	Login    string
	Password string
}

type VerifyCredentialsResult struct {
	UserID vo.UserID
}

type VerifyCredentialsHandler struct {
	users     UserByLoginProvider
	verifier  PasswordVerifier
	dummyHash domain.PasswordHash
}

func NewVerifyCredentialsHandler(users UserByLoginProvider, verifier PasswordVerifier, dummyHash domain.PasswordHash) VerifyCredentialsHandler {
	return VerifyCredentialsHandler{users: users, verifier: verifier, dummyHash: dummyHash}
}

func (h VerifyCredentialsHandler) Handle(ctx context.Context, cmd VerifyCredentialsCommand) (VerifyCredentialsResult, error) {
	login, err := domain.NewLogin(cmd.Login)
	if err != nil {
		return VerifyCredentialsResult{}, domain.ErrInvalidCredentials
	}

	password, err := domain.NewPassword(cmd.Password)
	if err != nil {
		return VerifyCredentialsResult{}, domain.ErrInvalidCredentials
	}

	user, err := h.users.ByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			_, _ = h.verifier.Compare(ctx, h.dummyHash, password)
			return VerifyCredentialsResult{}, domain.ErrInvalidCredentials
		}
		return VerifyCredentialsResult{}, fmt.Errorf("load user %q: %w", login, err)
	}

	ok, err := h.verifier.Compare(ctx, user.PasswordHash(), password)
	if err != nil {
		return VerifyCredentialsResult{}, fmt.Errorf("compare password: %w", err)
	}

	if !ok {
		return VerifyCredentialsResult{}, domain.ErrInvalidCredentials
	}

	return VerifyCredentialsResult{UserID: user.ID()}, nil
}
