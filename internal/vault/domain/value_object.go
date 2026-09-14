package domain

import "github.com/google/uuid"

type SecretID struct {
	value uuid.UUID
}

func SecretIDFromUUID(id uuid.UUID) (SecretID, error) {
	if id == uuid.Nil {
		return SecretID{}, ErrInvalidSecretID
	}
	return SecretID{value: id}, nil
}

func ParseSecretID(s string) (SecretID, error) {
	id, err := uuid.Parse(s)
	if err != nil || id == uuid.Nil {
		return SecretID{}, ErrInvalidSecretID
	}
	return SecretID{value: id}, nil
}

func (id SecretID) UUID() uuid.UUID { return id.value }

func (id SecretID) String() string { return id.value.String() }

func (id SecretID) IsZero() bool { return id.value == uuid.Nil }

type SecretType string

const (
	SecretTypeCredentials SecretType = "credentials"
	SecretTypeText        SecretType = "text"
	SecretTypeBinary      SecretType = "binary"
	SecretTypeCard        SecretType = "card"
)

func ParseSecretType(s string) (SecretType, error) {
	switch t := SecretType(s); t {
	case SecretTypeCredentials, SecretTypeText, SecretTypeBinary, SecretTypeCard:
		return t, nil
	default:
		return "", ErrUnknownSecretType
	}
}

func (t SecretType) String() string { return string(t) }

func (t SecretType) IsZero() bool { return t == "" }

const MaxPayloadSize = 1 << 20

type Payload struct {
	data []byte
}

func NewPayload(data []byte) (Payload, error) {
	if len(data) == 0 {
		return Payload{}, ErrEmptyPayload
	}
	if len(data) > MaxPayloadSize {
		return Payload{}, ErrPayloadTooLarge
	}
	return Payload{data: append([]byte(nil), data...)}, nil
}

func (p Payload) Bytes() []byte { return append([]byte(nil), p.data...) }

func (p Payload) IsZero() bool { return len(p.data) == 0 }

const MaxMetadataSize = 16 << 10

type Metadata struct {
	data []byte
}

func NewMetadata(data []byte) (Metadata, error) {
	if len(data) > MaxMetadataSize {
		return Metadata{}, ErrMetadataTooLarge
	}
	if len(data) == 0 {
		return Metadata{}, nil
	}
	return Metadata{data: append([]byte(nil), data...)}, nil
}

func (m Metadata) Bytes() []byte { return append([]byte(nil), m.data...) }

func (m Metadata) IsZero() bool { return len(m.data) == 0 }
