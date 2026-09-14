package domain

import (
	"crypto/subtle"

	"github.com/google/uuid"
)

type TokenID struct {
	value uuid.UUID
}

func TokenIDFromUUID(id uuid.UUID) (TokenID, error) {
	if id == uuid.Nil {
		return TokenID{}, ErrInvalidTokenID
	}
	return TokenID{value: id}, nil
}

func (id TokenID) UUID() uuid.UUID { return id.value }

func (id TokenID) String() string { return id.value.String() }

func (id TokenID) IsZero() bool { return id.value == uuid.Nil }

type TokenHash struct {
	value []byte
}

func NewTokenHash(b []byte) (TokenHash, error) {
	if len(b) == 0 {
		return TokenHash{}, ErrEmptyTokenHash
	}
	return TokenHash{value: append([]byte(nil), b...)}, nil
}

func (h TokenHash) Bytes() []byte { return append([]byte(nil), h.value...) }

func (h TokenHash) Equal(other TokenHash) bool {
	return subtle.ConstantTimeCompare(h.value, other.value) == 1
}

func (h TokenHash) String() string { return "[redacted]" }

func (h TokenHash) IsZero() bool { return len(h.value) == 0 }
