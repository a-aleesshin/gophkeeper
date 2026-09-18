package adapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	identityapi "github.com/a-aleesshin/gophkeeper/internal/identity/api"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type identityAPI interface {
	VerifyCredentials(ctx context.Context, login, password string) (vo.UserID, error)
}

type IdentityCredentialsVerifier struct {
	identity identityAPI
}

func NewIdentityCredentialsVerifier(identity identityAPI) IdentityCredentialsVerifier {
	return IdentityCredentialsVerifier{identity: identity}
}

func (v IdentityCredentialsVerifier) VerifyCredentials(ctx context.Context, login, password string) (vo.UserID, error) {
	userID, err := v.identity.VerifyCredentials(ctx, login, password)
	if err != nil {
		if errors.Is(err, identityapi.ErrInvalidCredentials) {
			return vo.UserID{}, domain.ErrInvalidCredentials
		}
		return vo.UserID{}, fmt.Errorf("identity: %w", err)
	}
	return userID, nil
}
