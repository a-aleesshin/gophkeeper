package postgres

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/migrations"
)

func setupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("TEST_DATABASE_DSN is not set")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db for migrations: %v", err)
	}
	defer db.Close()

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		t.Fatalf("migration source: %v", err)
	}
	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{})
	if err != nil {
		t.Fatalf("migration driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		t.Fatalf("migrate instance: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate up: %v", err)
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(context.Background(), "TRUNCATE users CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func createUser(t *testing.T, pool *pgxpool.Pool) vo.UserID {
	t.Helper()
	raw := uuid.Must(uuid.NewV7())
	_, err := pool.Exec(context.Background(),
		"INSERT INTO users (id, login, password_hash, created_at) VALUES ($1, $2, $3, now())",
		raw, "user-"+raw.String()[:8], []byte("hash"))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	userID, err := vo.UserIDFromUUID(raw)
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return userID
}

func makeToken(t *testing.T, userID vo.UserID, seed byte) domain.RefreshToken {
	t.Helper()
	id, err := domain.TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("TokenIDFromUUID: %v", err)
	}
	rawHash := make([]byte, 32)
	rawHash[0] = seed
	hash, err := domain.NewTokenHash(rawHash)
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	token, err := domain.NewRefreshToken(id, userID, hash, now, time.Hour)
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}
	return token
}

func TestRefreshTokenRepositoryCreateAndByID(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewRefreshTokenRepository(pool)
	ctx := context.Background()
	userID := createUser(t, pool)
	token := makeToken(t, userID, 1)

	// Act
	if err := repo.Create(ctx, token); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.ByID(ctx, token.ID())

	// Assert
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.ID() != token.ID() || got.UserID() != userID {
		t.Fatal("identity mismatch")
	}
	if !got.ExpiresAt().Equal(token.ExpiresAt()) || !got.CreatedAt().Equal(token.CreatedAt()) {
		t.Fatalf("timestamps mismatch: %v/%v", got.ExpiresAt(), got.CreatedAt())
	}
}

func TestRefreshTokenRepositoryByIDNotFound(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewRefreshTokenRepository(pool)
	unknown, err := domain.TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("TokenIDFromUUID: %v", err)
	}

	// Act
	_, err = repo.ByID(context.Background(), unknown)

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("ByID error = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshTokenRepositoryDeleteByID(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewRefreshTokenRepository(pool)
	ctx := context.Background()
	userID := createUser(t, pool)
	token := makeToken(t, userID, 2)
	if err := repo.Create(ctx, token); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Act
	if err := repo.DeleteByID(ctx, token.ID()); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}

	// Assert
	if _, err := repo.ByID(ctx, token.ID()); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("ByID after delete = %v, want ErrRefreshTokenNotFound", err)
	}
}

