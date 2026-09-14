package adapter

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
)

var ErrMalformedHash = errors.New("malformed password hash")

const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

type Argon2Hasher struct {
	time    uint32
	memory  uint32
	threads uint8
}

func NewArgon2Hasher() Argon2Hasher {
	return Argon2Hasher{time: argonTime, memory: argonMemory, threads: argonThreads}
}

func (h Argon2Hasher) Hash(_ context.Context, password domain.Password) (domain.PasswordHash, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return domain.PasswordHash{}, fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password.Reveal()), salt, h.time, h.memory, h.threads, argonKeyLen)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.time, h.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return domain.NewPasswordHash([]byte(encoded))
}

func (h Argon2Hasher) Compare(_ context.Context, hash domain.PasswordHash, password domain.Password) (bool, error) {
	parts := strings.Split(string(hash.Bytes()), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrMalformedHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrMalformedHash
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrMalformedHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMalformedHash
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrMalformedHash
	}

	key := argon2.IDKey([]byte(password.Reveal()), salt, time, memory, threads, uint32(len(expected)))

	return subtle.ConstantTimeCompare(key, expected) == 1, nil
}
