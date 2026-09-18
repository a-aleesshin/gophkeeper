package adapter

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
)

const refreshTokenSecretLen = 32

type RefreshTokenCodec struct{}

func NewRefreshTokenCodec() RefreshTokenCodec {
	return RefreshTokenCodec{}
}

func (c RefreshTokenCodec) New(id domain.TokenID) (string, domain.TokenHash, error) {
	if id.IsZero() {
		return "", domain.TokenHash{}, domain.ErrInvalidTokenID
	}
	raw := make([]byte, refreshTokenSecretLen)
	if _, err := rand.Read(raw); err != nil {
		return "", domain.TokenHash{}, fmt.Errorf("generate refresh token: %w", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	return id.String() + "." + secret, hashSecret(secret), nil
}

func (c RefreshTokenCodec) Parse(plaintext string) (domain.TokenID, domain.TokenHash, error) {
	idPart, secret, ok := strings.Cut(plaintext, ".")
	if !ok || secret == "" {
		return domain.TokenID{}, domain.TokenHash{}, domain.ErrRefreshTokenNotFound
	}
	rawID, err := uuid.Parse(idPart)
	if err != nil {
		return domain.TokenID{}, domain.TokenHash{}, domain.ErrRefreshTokenNotFound
	}
	id, err := domain.TokenIDFromUUID(rawID)
	if err != nil {
		return domain.TokenID{}, domain.TokenHash{}, domain.ErrRefreshTokenNotFound
	}
	return id, hashSecret(secret), nil
}

func hashSecret(secret string) domain.TokenHash {
	sum := sha256.Sum256([]byte(secret))
	hash, err := domain.NewTokenHash(sum[:])
	if err != nil {
		panic(fmt.Sprintf("token hash from sha256 sum: %v", err))
	}
	return hash
}
