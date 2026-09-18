package domain

import "errors"

var (
	ErrInvalidTokenID       = errors.New("invalid token id")
	ErrEmptyTokenHash       = errors.New("empty token hash")
	ErrInvalidTokenTTL      = errors.New("invalid token ttl")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrInvalidAccessToken   = errors.New("invalid access token")
	ErrAccessTokenExpired   = errors.New("access token expired")
	ErrInvalidCredentials   = errors.New("invalid credentials")
)
