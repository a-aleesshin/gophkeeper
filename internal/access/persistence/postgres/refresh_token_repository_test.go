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
		raw, "user-"+raw.String(), []byte("hash"))
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
	return makeTokenAt(t, userID, seed, time.Now().UTC().Truncate(time.Microsecond), time.Hour)
}

func makeTokenAt(t *testing.T, userID vo.UserID, seed byte, now time.Time, ttl time.Duration) domain.RefreshToken {
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

	token, err := domain.NewRefreshToken(id, userID, hash, now, ttl)
	if err != nil {
		t.Fatalf("NewRefreshToken: %v", err)
	}

	return token
}

func TestRefreshTokenRepositoryCreateAndConsume(t *testing.T) {
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
	got, err := repo.Consume(ctx, token.ID(), token.Hash())

	// Assert
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ID() != token.ID() || got.UserID() != userID {
		t.Fatal("identity mismatch")
	}
	if !got.ExpiresAt().Equal(token.ExpiresAt()) || !got.CreatedAt().Equal(token.CreatedAt()) {
		t.Fatalf("timestamps mismatch: %v/%v", got.ExpiresAt(), got.CreatedAt())
	}
	if _, err := repo.Consume(ctx, token.ID(), token.Hash()); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("second Consume = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshTokenRepositoryConsumeWrongHashKeepsRow(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewRefreshTokenRepository(pool)
	ctx := context.Background()
	userID := createUser(t, pool)
	token := makeToken(t, userID, 2)
	if err := repo.Create(ctx, token); err != nil {
		t.Fatalf("Create: %v", err)
	}
	wrong := make([]byte, 32)
	wrong[0] = 0xFF
	wrongHash, err := domain.NewTokenHash(wrong)
	if err != nil {
		t.Fatalf("NewTokenHash: %v", err)
	}

	// Act
	_, err = repo.Consume(ctx, token.ID(), wrongHash)

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("Consume error = %v, want ErrRefreshTokenNotFound", err)
	}
	if _, err := repo.Consume(ctx, token.ID(), token.Hash()); err != nil {
		t.Fatalf("row must survive wrong-hash consume: %v", err)
	}
}

func TestRefreshTokenRepositoryConsumeUnknown(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewRefreshTokenRepository(pool)
	userID := createUser(t, pool)
	token := makeToken(t, userID, 3)

	// Act
	_, err := repo.Consume(context.Background(), token.ID(), token.Hash())

	// Assert
	if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatalf("Consume error = %v, want ErrRefreshTokenNotFound", err)
	}
}

func TestRefreshTokenRepositoryDeleteExpiredByUser(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewRefreshTokenRepository(pool)
	ctx := context.Background()
	userID := createUser(t, pool)
	strangerID := createUser(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	expiredMine := makeTokenAt(t, userID, 4, now.Add(-2*time.Hour), time.Hour)
	aliveMine := makeTokenAt(t, userID, 5, now, time.Hour)
	expiredForeign := makeTokenAt(t, strangerID, 6, now.Add(-2*time.Hour), time.Hour)
	for _, token := range []domain.RefreshToken{expiredMine, aliveMine, expiredForeign} {
		if err := repo.Create(ctx, token); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	// Act
	if err := repo.DeleteExpiredByUser(ctx, userID, now); err != nil {
		t.Fatalf("DeleteExpiredByUser: %v", err)
	}

	// Assert
	if _, err := repo.Consume(ctx, expiredMine.ID(), expiredMine.Hash()); !errors.Is(err, domain.ErrRefreshTokenNotFound) {
		t.Fatal("expired own token must be deleted")
	}
	if _, err := repo.Consume(ctx, aliveMine.ID(), aliveMine.Hash()); err != nil {
		t.Fatalf("alive own token must survive: %v", err)
	}
	if _, err := repo.Consume(ctx, expiredForeign.ID(), expiredForeign.Hash()); err != nil {
		t.Fatalf("foreign token must survive: %v", err)
	}
}
