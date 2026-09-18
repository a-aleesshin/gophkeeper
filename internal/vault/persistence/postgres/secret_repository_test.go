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

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	platformpg "github.com/a-aleesshin/gophkeeper/internal/platform/postgres"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
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

func createOwner(t *testing.T, pool *pgxpool.Pool) vo.UserID {
	t.Helper()

	raw := uuid.Must(uuid.NewV7())
	_, err := pool.Exec(context.Background(),
		"INSERT INTO users (id, login, password_hash, created_at) VALUES ($1, $2, $3, now())",
		raw, "owner-"+raw.String(), []byte("hash"))

	if err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	owner, err := vo.UserIDFromUUID(raw)

	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return owner
}

func makeSecret(t *testing.T, owner vo.UserID, now time.Time) domain.Secret {
	t.Helper()
	id, err := domain.SecretIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("SecretIDFromUUID: %v", err)
	}

	payload, err := domain.NewPayload([]byte("ciphertext"))
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}

	metadata, err := domain.NewMetadata([]byte("encrypted-meta"))
	if err != nil {
		t.Fatalf("NewMetadata: %v", err)
	}

	secret, err := domain.NewSecret(id, owner, domain.SecretTypeCredentials, payload, metadata, now)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	return secret
}

func TestSecretRepositoryCreateAndGet(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	secret := makeSecret(t, owner, now)

	// Act
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.Get(ctx, owner, secret.ID())

	// Assert
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID() != secret.ID() || got.OwnerID() != owner {
		t.Fatal("identity mismatch")
	}

	if got.Type() != domain.SecretTypeCredentials || got.Version() != 1 || got.IsDeleted() {
		t.Fatalf("state mismatch: %+v", got)
	}

	if string(got.Payload().Bytes()) != "ciphertext" || string(got.Metadata().Bytes()) != "encrypted-meta" {
		t.Fatal("payload/metadata mismatch")
	}

	if !got.CreatedAt().Equal(now) || !got.UpdatedAt().Equal(now) {
		t.Fatalf("timestamps mismatch: %v/%v", got.CreatedAt(), got.UpdatedAt())
	}
}

func TestSecretRepositoryCreateDuplicate(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	secret := makeSecret(t, owner, time.Now().UTC())
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	// Act
	err := repo.Create(ctx, secret)

	// Assert
	if !errors.Is(err, domain.ErrSecretAlreadyExists) {
		t.Fatalf("Create error = %v, want ErrSecretAlreadyExists", err)
	}
}

func TestSecretRepositoryGetForeignOwner(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	stranger := createOwner(t, pool)
	secret := makeSecret(t, owner, time.Now().UTC())
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Act
	_, err := repo.Get(ctx, stranger, secret.ID())

	// Assert
	if !errors.Is(err, domain.ErrSecretNotFound) {
		t.Fatalf("Get error = %v, want ErrSecretNotFound", err)
	}
}

func TestSecretRepositorySaveVersionGuard(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	secret := makeSecret(t, owner, now)
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Create: %v", err)
	}

	payload, err := domain.NewPayload([]byte("v2"))
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}

	updated, err := secret.Update(payload, domain.Metadata{}, 1, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Act
	if err := repo.Save(ctx, updated); err != nil {
		t.Fatalf("Save: %v", err)
	}
	staleErr := repo.Save(ctx, updated)

	// Assert
	got, err := repo.Get(ctx, owner, secret.ID())

	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Version() != 2 || string(got.Payload().Bytes()) != "v2" {
		t.Fatalf("saved state mismatch: v%d %q", got.Version(), got.Payload().Bytes())
	}

	if !errors.Is(staleErr, domain.ErrVersionConflict) {
		t.Fatalf("stale Save error = %v, want ErrVersionConflict", staleErr)
	}
}

func TestSecretRepositorySaveTombstone(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	secret := makeSecret(t, owner, now)
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Create: %v", err)
	}

	deleted, err := secret.Delete(1, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Act
	if err := repo.Save(ctx, deleted); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Assert
	got, err := repo.Get(ctx, owner, secret.ID())

	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !got.IsDeleted() || !got.Payload().IsZero() || got.Version() != 2 {
		t.Fatalf("tombstone mismatch: deleted=%v payloadZero=%v v%d", got.IsDeleted(), got.Payload().IsZero(), got.Version())
	}
}

func TestSecretRepositoryListByOwnerExcludesDeleted(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	alive := makeSecret(t, owner, now)
	dead := makeSecret(t, owner, now)

	deadTombstone, err := dead.Delete(1, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	for _, s := range []domain.Secret{alive, dead} {
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := repo.Save(ctx, deadTombstone); err != nil {
		t.Fatalf("Save tombstone: %v", err)
	}

	// Act
	items, err := repo.ListByOwner(ctx, owner)

	// Assert
	if err != nil {
		t.Fatalf("ListByOwner: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}

	if items[0].SecretID != alive.ID().String() {
		t.Fatalf("items[0] = %s, want %s", items[0].SecretID, alive.ID())
	}
}

func TestSecretRepositoryListChangedSince(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	base := time.Now().UTC().Truncate(time.Microsecond)
	old := makeSecret(t, owner, base.Add(-time.Hour))
	fresh := makeSecret(t, owner, base.Add(time.Minute))
	tombstoned := makeSecret(t, owner, base.Add(-time.Hour))

	tombstone, err := tombstoned.Delete(1, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	for _, s := range []domain.Secret{old, fresh, tombstoned} {
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	if err := repo.Save(ctx, tombstone); err != nil {
		t.Fatalf("Save tombstone: %v", err)
	}

	// Act
	changed, err := repo.ListChangedSince(ctx, owner, base)

	// Assert
	if err != nil {
		t.Fatalf("ListChangedSince: %v", err)
	}
	if len(changed) != 2 {
		t.Fatalf("changed = %d, want 2 (fresh + tombstone)", len(changed))
	}

	ids := map[string]bool{}
	for _, s := range changed {
		ids[s.ID().String()] = true
	}

	if !ids[fresh.ID().String()] || !ids[tombstoned.ID().String()] {
		t.Fatalf("changed ids = %v", ids)
	}
}

func TestTxRunnerRollbackOnError(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	runner := platformpg.NewTxRunner(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	secret := makeSecret(t, owner, time.Now().UTC())
	boom := errors.New("boom")

	// Act
	err := runner.InTx(ctx, func(ctx context.Context) error {
		if err := repo.Create(ctx, secret); err != nil {
			return err
		}
		return boom
	})

	// Assert
	if !errors.Is(err, boom) {
		t.Fatalf("InTx error = %v, want boom", err)
	}
	if _, err := repo.Get(ctx, owner, secret.ID()); !errors.Is(err, domain.ErrSecretNotFound) {
		t.Fatalf("Get after rollback = %v, want ErrSecretNotFound", err)
	}
}

func TestSecretRepositoryEmptyMetadataAndTombstoneRoundtrip(t *testing.T) {
	// Arrange
	pool := setupPool(t)
	repo := NewSecretRepository(pool)
	ctx := context.Background()
	owner := createOwner(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	id, err := domain.SecretIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("SecretIDFromUUID: %v", err)
	}
	payload, err := domain.NewPayload([]byte("ciphertext"))
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}
	secret, err := domain.NewSecret(id, owner, domain.SecretTypeText, payload, domain.Metadata{}, now)
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}

	// Act
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Create with empty metadata: %v", err)
	}
	deleted, err := secret.Delete(1, now.Add(time.Second))
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := repo.Save(ctx, deleted); err != nil {
		t.Fatalf("Save tombstone with nil payload: %v", err)
	}

	// Assert
	got, err := repo.Get(ctx, owner, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.IsDeleted() || !got.Payload().IsZero() || !got.Metadata().IsZero() {
		t.Fatalf("tombstone state mismatch: %+v", got)
	}
}
