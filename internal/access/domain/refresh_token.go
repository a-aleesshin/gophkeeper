package domain

import (
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type RefreshToken struct {
	id        TokenID
	userID    vo.UserID
	hash      TokenHash
	expiresAt time.Time
	createdAt time.Time
}

func NewRefreshToken(id TokenID, userID vo.UserID, hash TokenHash, now time.Time, ttl time.Duration) (RefreshToken, error) {
	if id.IsZero() {
		return RefreshToken{}, ErrInvalidTokenID
	}
	if userID.IsZero() {
		return RefreshToken{}, vo.ErrInvalidUserID
	}
	if hash.IsZero() {
		return RefreshToken{}, ErrEmptyTokenHash
	}
	if ttl <= 0 {
		return RefreshToken{}, ErrInvalidTokenTTL
	}

	return RefreshToken{
		id:        id,
		userID:    userID,
		hash:      hash,
		expiresAt: now.Add(ttl),
		createdAt: now,
	}, nil
}

func RestoreRefreshToken(id TokenID, userID vo.UserID, hash TokenHash, expiresAt, createdAt time.Time) RefreshToken {
	return RefreshToken{id: id, userID: userID, hash: hash, expiresAt: expiresAt, createdAt: createdAt}
}

func (t RefreshToken) IsExpired(now time.Time) bool { return !now.Before(t.expiresAt) }

func (t RefreshToken) ID() TokenID { return t.id }

func (t RefreshToken) UserID() vo.UserID { return t.userID }

func (t RefreshToken) Hash() TokenHash { return t.hash }

func (t RefreshToken) ExpiresAt() time.Time { return t.expiresAt }

func (t RefreshToken) CreatedAt() time.Time { return t.createdAt }
