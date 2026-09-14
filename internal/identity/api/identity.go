package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	"github.com/a-aleesshin/gophkeeper/internal/identity/usecase"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type Identity struct {
	verify usecase.VerifyCredentialsHandler
}

func NewIdentity(verify usecase.VerifyCredentialsHandler) *Identity {
	return &Identity{verify: verify}
}

func (a *Identity) VerifyCredentials(ctx context.Context, login, password string) (vo.UserID, error) {
	result, err := a.verify.Handle(ctx, usecase.VerifyCredentialsCommand{Login: login, Password: password})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			return vo.UserID{}, ErrInvalidCredentials
		}
		return vo.UserID{}, fmt.Errorf("verify credentials: %w", err)
	}
	return result.UserID, nil
}
