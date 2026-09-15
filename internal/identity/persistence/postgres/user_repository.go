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

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

const uniqueViolationCode = "23505"

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, user domain.User) error {
	const query = `INSERT INTO users (id, login, password_hash, created_at) VALUES ($1, $2, $3, $4)`

	_, err := r.pool.Exec(ctx, query,
		user.ID().UUID(),
		user.Login().String(),
		user.PasswordHash().Bytes(),
		user.CreatedAt(),
	)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == uniqueViolationCode {
			return domain.ErrLoginTaken
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (r *UserRepository) ByLogin(ctx context.Context, login domain.Login) (domain.User, error) {
	const query = `SELECT id, login, password_hash, created_at FROM users WHERE login = $1`

	var (
		id        uuid.UUID
		rawLogin  string
		rawHash   []byte
		createdAt time.Time
	)
	err := r.pool.QueryRow(ctx, query, login.String()).Scan(&id, &rawLogin, &rawHash, &createdAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, domain.ErrUserNotFound
		}
		return domain.User{}, fmt.Errorf("select user by login: %w", err)
	}

	return restoreUser(id, rawLogin, rawHash, createdAt)
}

func restoreUser(id uuid.UUID, rawLogin string, rawHash []byte, createdAt time.Time) (domain.User, error) {
	userID, err := vo.UserIDFromUUID(id)
	if err != nil {
		return domain.User{}, fmt.Errorf("restore user id: %w", err)
	}

	login, err := domain.RestoreLogin(rawLogin)
	if err != nil {
		return domain.User{}, fmt.Errorf("restore login %q: %w", rawLogin, err)
	}

	hash, err := domain.NewPasswordHash(rawHash)
	if err != nil {
		return domain.User{}, fmt.Errorf("restore password hash: %w", err)
	}

	return domain.RestoreUser(userID, login, hash, createdAt), nil
}
