package domain

import "errors"

var (
	ErrInvalidSecretID   = errors.New("invalid secret id")
	ErrUnknownSecretType = errors.New("unknown secret type")
	ErrSecretTypeMismatch = errors.New("secret type mismatch")
	ErrEmptyPayload      = errors.New("payload is empty")
	ErrPayloadTooLarge   = errors.New("payload exceeds size limit")
	ErrMetadataTooLarge  = errors.New("metadata exceeds size limit")
	ErrSecretNotFound    = errors.New("secret not found")
	ErrSecretAlreadyExists = errors.New("secret already exists")
	ErrSecretDeleted     = errors.New("secret is deleted")
	ErrVersionConflict   = errors.New("secret version conflict")
)
