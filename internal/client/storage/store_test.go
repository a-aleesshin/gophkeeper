package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(filepath.Join(t.TempDir(), "nested", "vault.json"))
}

func TestStoreRoundtrip(t *testing.T) {
	// Arrange
	store := testStore(t)
	vault := NewVault()
	vault.Cursor = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	vault.Put("id-1", "credentials", []byte("envelope"), []byte("meta-envelope"), vault.Cursor)

	// Act
	if err := store.Save(vault); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.Cursor.Equal(vault.Cursor) {
		t.Fatalf("Cursor = %v, want %v", got.Cursor, vault.Cursor)
	}
	rec, ok := got.Get("id-1")
	if !ok {
		t.Fatal("record lost in roundtrip")
	}
	if string(rec.Payload) != "envelope" || !rec.Dirty {
		t.Fatalf("record = %+v", rec)
	}
}

func TestStoreLoadMissingFile(t *testing.T) {
	// Act
	vault, err := testStore(t).Load()

	// Assert
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(vault.Records) != 0 {
		t.Fatal("missing file must load as empty vault")
	}
}

func TestStoreFilePermissions(t *testing.T) {
	// Arrange
	store := testStore(t)

	// Act
	if err := store.Save(NewVault()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Assert
	info, err := os.Stat(store.path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("permissions = %o, want 600", perm)
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
	if err == nil {
		t.Fatal("Load accepted corrupted vault")
	}
}

func TestStoreSaveOverwritesAtomically(t *testing.T) {
	// Arrange
	store := testStore(t)
	first := NewVault()
	first.Put("id-1", "text", []byte("v1"), nil, time.Now().UTC())
	if err := store.Save(first); err != nil {
		t.Fatalf("Save: %v", err)
	}
	second := NewVault()
	second.Put("id-2", "text", []byte("v2"), nil, time.Now().UTC())

	// Act
	if err := store.Save(second); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Assert
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := got.Get("id-1"); ok {
		t.Fatal("old record survived overwrite")
	}
	if _, ok := got.Get("id-2"); !ok {
		t.Fatal("new record missing after overwrite")
	}
	entries, err := os.ReadDir(filepath.Dir(store.path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("dir entries = %d, want 1 (no leftover temp files)", len(entries))
	}
}
