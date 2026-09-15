package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	platformpg "github.com/a-aleesshin/gophkeeper/internal/platform/postgres"
)

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{pool: pool}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, token domain.RefreshToken) error {
	const query = `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`

	q := platformpg.QuerierFrom(ctx, r.pool)
	_, err := q.Exec(ctx, query,
		token.ID().UUID(),
		token.UserID().UUID(),
		token.Hash().Bytes(),
		token.ExpiresAt(),
		token.CreatedAt(),
	)
	if err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) Consume(ctx context.Context, tokenID domain.TokenID, hash domain.TokenHash) (domain.RefreshToken, error) {
	const query = `
		DELETE FROM refresh_tokens
		WHERE id = $1 AND token_hash = $2
		RETURNING id, user_id, token_hash, expires_at, created_at`

	q := platformpg.QuerierFrom(ctx, r.pool)
	var (
		id        uuid.UUID
		userID    uuid.UUID
		rawHash   []byte
		expiresAt time.Time
		createdAt time.Time
	)
	err := q.QueryRow(ctx, query, tokenID.UUID(), hash.Bytes()).Scan(&id, &userID, &rawHash, &expiresAt, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RefreshToken{}, domain.ErrRefreshTokenNotFound
		}
		return domain.RefreshToken{}, fmt.Errorf("consume refresh token: %w", err)
	}

	return restoreRefreshToken(id, userID, rawHash, expiresAt, createdAt)
}

func (r *RefreshTokenRepository) DeleteExpiredByUser(ctx context.Context, userID vo.UserID, now time.Time) error {
	const query = `DELETE FROM refresh_tokens WHERE user_id = $1 AND expires_at <= $2`

	q := platformpg.QuerierFrom(ctx, r.pool)
	if _, err := q.Exec(ctx, query, userID.UUID(), now); err != nil {
		return fmt.Errorf("delete expired tokens: %w", err)
	}
	return nil
}

func restoreRefreshToken(id, userID uuid.UUID, rawHash []byte, expiresAt, createdAt time.Time) (domain.RefreshToken, error) {
	tokenID, err := domain.TokenIDFromUUID(id)
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("restore token id: %w", err)
	}
	owner, err := vo.UserIDFromUUID(userID)
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("restore user id: %w", err)
	}
	tokenHash, err := domain.NewTokenHash(rawHash)
	if err != nil {
		return domain.RefreshToken{}, fmt.Errorf("restore token hash: %w", err)
	}
	return domain.RestoreRefreshToken(tokenID, owner, tokenHash, expiresAt, createdAt), nil
}
