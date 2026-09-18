package session

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "nested", "session.json"))
}

func TestStoreRoundtrip(t *testing.T) {
	// Arrange
	store := testStore(t)
	sess := Session{
		Login:           "alice",
		AccessToken:     "jwt-token",
		AccessExpiresAt: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		RefreshToken:    "id.secret",
		EncryptionKey:   []byte{1, 2, 3},
	}

	// Act
	if err := store.Save(sess); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Login != sess.Login || got.AccessToken != sess.AccessToken || got.RefreshToken != sess.RefreshToken {
		t.Fatalf("Load = %+v, want %+v", got, sess)
	}
	if !got.AccessExpiresAt.Equal(sess.AccessExpiresAt) {
		t.Fatalf("AccessExpiresAt = %v, want %v", got.AccessExpiresAt, sess.AccessExpiresAt)
	}
	if string(got.EncryptionKey) != string(sess.EncryptionKey) {
		t.Fatal("EncryptionKey mismatch")
	}
}

func TestStoreFilePermissions(t *testing.T) {
	// Arrange
	store := testStore(t)

	// Act
	if err := store.Save(Session{Login: "alice"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Assert
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file permissions = %o, want 600", perm)
	}
}

func TestStoreLoadNoSession(t *testing.T) {
	// Act
	_, err := testStore(t).Load()

	// Assert
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("Load error = %v, want ErrNoSession", err)
	}
}

func TestStoreClear(t *testing.T) {
	// Arrange
	store := testStore(t)
	if err := store.Save(Session{Login: "alice"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Act
	if err := store.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	// Assert
	if _, err := store.Load(); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Load after Clear = %v, want ErrNoSession", err)
	}
	if err := store.Clear(); err != nil {
		t.Fatalf("repeated Clear: %v", err)
	}
}

func TestStoreLoadCorrupted(t *testing.T) {
	// Arrange
	store := testStore(t)
	if err := os.MkdirAll(filepath.Dir(store.path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(store.path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Act
	_, err := store.Load()

	// Assert
	if err == nil || errors.Is(err, ErrNoSession) {
		t.Fatalf("Load error = %v, want parse error", err)
	}
}
