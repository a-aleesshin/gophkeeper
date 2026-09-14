package domain

import (
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type User struct {
	id           vo.UserID
	login        Login
	passwordHash PasswordHash
	createdAt    time.Time
}

func NewUser(id vo.UserID, login Login, hash PasswordHash, now time.Time) (User, error) {
	if id.IsZero() {
		return User{}, vo.ErrInvalidUserID
	}

	if login.IsZero() {
		return User{}, ErrInvalidLogin
	}

	if hash.IsZero() {
		return User{}, ErrEmptyPasswordHash
	}

	return User{id: id, login: login, passwordHash: hash, createdAt: now}, nil
}

func RestoreUser(id vo.UserID, login Login, hash PasswordHash, createdAt time.Time) User {
	return User{id: id, login: login, passwordHash: hash, createdAt: createdAt}
}

func (u User) ID() vo.UserID { return u.id }

func (u User) Login() Login { return u.login }

func (u User) PasswordHash() PasswordHash { return u.passwordHash }

func (u User) CreatedAt() time.Time { return u.createdAt }
