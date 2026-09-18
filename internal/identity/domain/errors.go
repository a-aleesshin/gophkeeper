package domain

import "errors"

var (
	ErrInvalidLogin       = errors.New("invalid login")
	ErrWeakPassword       = errors.New("password does not meet requirements")
	ErrEmptyPasswordHash  = errors.New("empty password hash")
	ErrLoginTaken         = errors.New("login already taken")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)
