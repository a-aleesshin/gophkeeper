package idgen

import "github.com/google/uuid"

type Generator interface {
	NewID() (uuid.UUID, error)
}

type V7 struct{}

func (V7) NewID() (uuid.UUID, error) { return uuid.NewV7() }
