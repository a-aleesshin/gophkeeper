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

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
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
		t.Fatalf("truncate users: %v", err)
	}
	return pool
}

func makeUser(t *testing.T, login string) domain.User {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	l, err := domain.NewLogin(login)
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}
	hash, err := domain.NewPasswordHash([]byte("$argon2id$fake"))
	if err != nil {
		t.Fatalf("NewPasswordHash: %v", err)
	}
	user, err := domain.NewUser(id, l, hash, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	return user
}

func TestUserRepositoryCreateAndByLogin(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewUserRepository(pool)
	ctx := context.Background()
	user := makeUser(t, "alice")

	// Act
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.ByLogin(ctx, user.Login())

	// Assert
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if got.ID() != user.ID() {
		t.Fatalf("ID = %v, want %v", got.ID(), user.ID())
	}
	if got.Login() != user.Login() {
		t.Fatalf("Login = %v, want %v", got.Login(), user.Login())
	}
	if string(got.PasswordHash().Bytes()) != string(user.PasswordHash().Bytes()) {
		t.Fatal("PasswordHash mismatch")
	}
	if !got.CreatedAt().Equal(user.CreatedAt()) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt(), user.CreatedAt())
	}
}

func TestUserRepositoryDuplicateLogin(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewUserRepository(pool)
	ctx := context.Background()
	if err := repo.Create(ctx, makeUser(t, "alice")); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// Act
	err := repo.Create(ctx, makeUser(t, "alice"))

	// Assert
	if !errors.Is(err, domain.ErrLoginTaken) {
		t.Fatalf("Create error = %v, want ErrLoginTaken", err)
	}
}

func TestUserRepositoryByLoginNotFound(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewUserRepository(pool)
	login, err := domain.NewLogin("ghost")
	if err != nil {
		t.Fatalf("NewLogin: %v", err)
	}

	// Act
	_, err = repo.ByLogin(context.Background(), login)

	// Assert
	if !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("ByLogin error = %v, want ErrUserNotFound", err)
	}
}
