package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	platformpg "github.com/a-aleesshin/gophkeeper/internal/platform/postgres"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
	"github.com/a-aleesshin/gophkeeper/internal/vault/usecase"
)

const uniqueViolationCode = "23505"

type SecretRepository struct {
	pool *pgxpool.Pool
}

func NewSecretRepository(pool *pgxpool.Pool) *SecretRepository {
	return &SecretRepository{pool: pool}
}

func (r *SecretRepository) Create(ctx context.Context, secret domain.Secret) error {
	const query = `
		INSERT INTO secrets (id, owner_id, type, payload, metadata, version, deleted, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	q := platformpg.QuerierFrom(ctx, r.pool)
	_, err := q.Exec(ctx, query,
		secret.ID().UUID(),
		secret.OwnerID().UUID(),
		secret.Type().String(),
		secret.Payload().Bytes(),
		secret.Metadata().Bytes(),
		secret.Version(),
		secret.IsDeleted(),
		secret.CreatedAt(),
		secret.UpdatedAt(),
	)

	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == uniqueViolationCode {
			return domain.ErrSecretAlreadyExists
		}
		return fmt.Errorf("insert secret: %w", err)
	}

	return nil
}

func (r *SecretRepository) Get(ctx context.Context, ownerID vo.UserID, id domain.SecretID) (domain.Secret, error) {
	const query = `
		SELECT id, owner_id, type, payload, metadata, version, deleted, created_at, updated_at
		FROM secrets
		WHERE id = $1 AND owner_id = $2`

	q := platformpg.QuerierFrom(ctx, r.pool)
	row := q.QueryRow(ctx, query, id.UUID(), ownerID.UUID())
	secret, err := scanSecret(row)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Secret{}, domain.ErrSecretNotFound
		}
		return domain.Secret{}, fmt.Errorf("select secret: %w", err)
	}

	return secret, nil
}

func (r *SecretRepository) Save(ctx context.Context, secret domain.Secret) error {
	const query = `
		UPDATE secrets
		SET payload = $1, metadata = $2, version = $3, deleted = $4, updated_at = $5
		WHERE id = $6 AND owner_id = $7 AND version = $8`

	q := platformpg.QuerierFrom(ctx, r.pool)
	tag, err := q.Exec(ctx, query,
		secret.Payload().Bytes(),
		secret.Metadata().Bytes(),
		secret.Version(),
		secret.IsDeleted(),
		secret.UpdatedAt(),
		secret.ID().UUID(),
		secret.OwnerID().UUID(),
		secret.Version()-1,
	)

	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrVersionConflict
	}

	return nil
}

func (r *SecretRepository) ListByOwner(ctx context.Context, ownerID vo.UserID) ([]usecase.SecretHeader, error) {
	const query = `
		SELECT id, type, metadata, version, updated_at
		FROM secrets
		WHERE owner_id = $1 AND NOT deleted
		ORDER BY updated_at DESC`

	q := platformpg.QuerierFrom(ctx, r.pool)

	rows, err := q.Query(ctx, query, ownerID.UUID())
	if err != nil {
		return nil, fmt.Errorf("select secret headers: %w", err)
	}

	defer rows.Close()

	var out []usecase.SecretHeader
	for rows.Next() {
		var (
			id        uuid.UUID
			rawType   string
			metadata  []byte
			version   int64
			updatedAt time.Time
		)

		if err := rows.Scan(&id, &rawType, &metadata, &version, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan secret header: %w", err)
		}

		out = append(out, usecase.SecretHeader{
			SecretID:  id.String(),
			Type:      rawType,
			Metadata:  metadata,
			Version:   version,
			UpdatedAt: updatedAt,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret headers: %w", err)
	}

	return out, nil
}

func (r *SecretRepository) ListChangedSince(ctx context.Context, ownerID vo.UserID, since time.Time) ([]domain.Secret, error) {
	const query = `
		SELECT id, owner_id, type, payload, metadata, version, deleted, created_at, updated_at
		FROM secrets
		WHERE owner_id = $1 AND updated_at > $2
		ORDER BY updated_at`

	q := platformpg.QuerierFrom(ctx, r.pool)

	rows, err := q.Query(ctx, query, ownerID.UUID(), since)
	if err != nil {
		return nil, fmt.Errorf("select changed secrets: %w", err)
	}

	defer rows.Close()

	var out []domain.Secret
	for rows.Next() {
		secret, err := scanSecret(rows)
		if err != nil {
			return nil, fmt.Errorf("scan changed secret: %w", err)
		}
		out = append(out, secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate changed secrets: %w", err)
	}

	return out, nil
}

func scanSecret(row pgx.Row) (domain.Secret, error) {
	var (
		id        uuid.UUID
		ownerID   uuid.UUID
		rawType   string
		payload   []byte
		metadata  []byte
		version   int64
		deleted   bool
		createdAt time.Time
		updatedAt time.Time
	)

	if err := row.Scan(&id, &ownerID, &rawType, &payload, &metadata, &version, &deleted, &createdAt, &updatedAt); err != nil {
		return domain.Secret{}, err
	}

	return restoreSecret(id, ownerID, rawType, payload, metadata, version, deleted, createdAt, updatedAt)
}

func restoreSecret(id, ownerID uuid.UUID, rawType string, rawPayload, rawMetadata []byte,
	version int64, deleted bool, createdAt, updatedAt time.Time) (domain.Secret, error) {
	secretID, err := domain.SecretIDFromUUID(id)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("restore secret id: %w", err)
	}

	owner, err := vo.UserIDFromUUID(ownerID)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("restore owner id: %w", err)
	}

	secretType, err := domain.ParseSecretType(rawType)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("restore type %q: %w", rawType, err)
	}

	var payload domain.Payload
	if len(rawPayload) > 0 {
		payload, err = domain.NewPayload(rawPayload)
		if err != nil {
			return domain.Secret{}, fmt.Errorf("restore payload: %w", err)
		}
	}

	metadata, err := domain.NewMetadata(rawMetadata)
	if err != nil {
		return domain.Secret{}, fmt.Errorf("restore metadata: %w", err)
	}

	return domain.RestoreSecret(secretID, owner, secretType, payload, metadata, version, deleted, createdAt, updatedAt), nil
}
