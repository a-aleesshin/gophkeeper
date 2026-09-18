package valueobject

import (
	"errors"

	"github.com/google/uuid"
)

var ErrInvalidUserID = errors.New("invalid user id")

type UserID struct {
	value uuid.UUID
}

func UserIDFromUUID(id uuid.UUID) (UserID, error) {
	if id == uuid.Nil {
		return UserID{}, ErrInvalidUserID
	}
	return UserID{value: id}, nil
}

func ParseUserID(s string) (UserID, error) {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil {
		return UserID{}, ErrInvalidUserID
	}
	return UserID{value: id}, nil
}

func (id UserID) UUID() uuid.UUID { return id.value }

func (id UserID) String() string { return id.value.String() }

func (id UserID) IsZero() bool { return id.value == uuid.Nil }
