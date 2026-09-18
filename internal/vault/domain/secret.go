package domain

import (
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type Secret struct {
	id         SecretID
	ownerID    vo.UserID
	secretType SecretType
	payload    Payload
	metadata   Metadata
	version    int64
	deleted    bool
	createdAt  time.Time
	updatedAt  time.Time
}

func NewSecret(id SecretID, ownerID vo.UserID, t SecretType, payload Payload, metadata Metadata, now time.Time) (Secret, error) {
	if id.IsZero() {
		return Secret{}, ErrInvalidSecretID
	}

	if ownerID.IsZero() {
		return Secret{}, vo.ErrInvalidUserID
	}

	if _, err := ParseSecretType(t.String()); err != nil {
		return Secret{}, err
	}

	if payload.IsZero() {
		return Secret{}, ErrEmptyPayload
	}

	return Secret{
		id:         id,
		ownerID:    ownerID,
		secretType: t,
		payload:    payload,
		metadata:   metadata,
		version:    1,
		createdAt:  now,
		updatedAt:  now,
	}, nil
}

func RestoreSecret(
	id SecretID,
	ownerID vo.UserID,
	t SecretType,
	payload Payload,
	metadata Metadata,
	version int64,
	deleted bool,
	createdAt,
	updatedAt time.Time,
) Secret {
	return Secret{
		id:         id,
		ownerID:    ownerID,
		secretType: t,
		payload:    payload,
		metadata:   metadata,
		version:    version,
		deleted:    deleted,
		createdAt:  createdAt,
		updatedAt:  updatedAt,
	}
}

func (s Secret) Update(payload Payload, metadata Metadata, expectedVersion int64, now time.Time) (Secret, error) {
	if s.deleted {
		return s, ErrSecretDeleted
	}
	if s.version != expectedVersion {
		return s, ErrVersionConflict
	}
	if payload.IsZero() {
		return s, ErrEmptyPayload
	}
	s.payload = payload
	s.metadata = metadata
	s.version++
	s.updatedAt = now
	return s, nil
}

func (s Secret) Delete(expectedVersion int64, now time.Time) (Secret, error) {
	if s.deleted {
		return s, nil
	}
	if s.version != expectedVersion {
		return s, ErrVersionConflict
	}
	s.payload = Payload{}
	s.metadata = Metadata{}
	s.version++
	s.deleted = true
	s.updatedAt = now
	return s, nil
}

func (s Secret) ID() SecretID { return s.id }

func (s Secret) OwnerID() vo.UserID { return s.ownerID }

func (s Secret) Type() SecretType { return s.secretType }

func (s Secret) Payload() Payload { return s.payload }

func (s Secret) Metadata() Metadata { return s.metadata }

func (s Secret) Version() int64 { return s.version }

func (s Secret) IsDeleted() bool { return s.deleted }

func (s Secret) CreatedAt() time.Time { return s.createdAt }

func (s Secret) UpdatedAt() time.Time { return s.updatedAt }
