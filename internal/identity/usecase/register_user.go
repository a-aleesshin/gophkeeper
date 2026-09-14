package usecase

import (
	"context"
	"fmt"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
)

type UserCreator interface {
	Create(ctx context.Context, user domain.User) error
}

type PasswordHasher interface {
	Hash(ctx context.Context, password domain.Password) (domain.PasswordHash, error)
}

type RegisterUserCommand struct {
	Login    string
	Password string
}

type RegisterUserResult struct {
	UserID string
}

type RegisterUserHandler struct {
	users  UserCreator
	hasher PasswordHasher
	clock  clock.Clock
	ids    idgen.Generator
}

func NewRegisterUserHandler(users UserCreator, hasher PasswordHasher, clk clock.Clock, ids idgen.Generator) RegisterUserHandler {
	return RegisterUserHandler{users: users, hasher: hasher, clock: clk, ids: ids}
}

func (h RegisterUserHandler) Handle(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResult, error) {
	login, err := domain.NewLogin(cmd.Login)
	if err != nil {
		return RegisterUserResult{}, err
	}

	password, err := domain.NewPassword(cmd.Password)
	if err != nil {
		return RegisterUserResult{}, err
	}

	hash, err := h.hasher.Hash(ctx, password)
	if err != nil {
		return RegisterUserResult{}, fmt.Errorf("hash password: %w", err)
	}

	rawID, err := h.ids.NewID()
	if err != nil {
		return RegisterUserResult{}, fmt.Errorf("generate user id: %w", err)
	}

	id, err := vo.UserIDFromUUID(rawID)
	if err != nil {
		return RegisterUserResult{}, fmt.Errorf("generate user id: %w", err)
	}

	user, err := domain.NewUser(id, login, hash, h.clock.Now())
	if err != nil {
		return RegisterUserResult{}, err
	}

	if err := h.users.Create(ctx, user); err != nil {
		return RegisterUserResult{}, fmt.Errorf("create user %q: %w", login, err)
	}

	return RegisterUserResult{UserID: user.ID().String()}, nil
}
