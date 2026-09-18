package storage

import (
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Hour)
	t2 = t0.Add(2 * time.Hour)
)

func TestVaultPutAndList(t *testing.T) {
	// Arrange
	v := NewVault()

	// Act
	v.Put("id-1", "credentials", []byte("enc-1"), []byte("meta-1"), t0)
	v.Put("id-2", "card", []byte("enc-2"), nil, t1)

	// Assert
	items := v.List()
	if len(items) != 2 {
		t.Fatalf("List = %d items, want 2", len(items))
	}
	if items[0].ID != "id-2" || items[1].ID != "id-1" {
		t.Fatalf("List order = %s, %s; want newest first", items[0].ID, items[1].ID)
	}
	if !items[0].Dirty || !items[1].Dirty {
		t.Fatal("local puts must be dirty")
	}
}

func TestVaultPutPreservesVersion(t *testing.T) {
	// Arrange
	v := NewVault()
	v.ApplyServer(Record{ID: "id-1", Type: "text", Payload: []byte("server"), Version: 3, UpdatedAt: t0})

	// Act
	v.Put("id-1", "text", []byte("local-edit"), nil, t1)

	// Assert
	rec, _ := v.Get("id-1")
	if rec.Version != 3 {
		t.Fatalf("Version = %d, want 3 (base version for sync)", rec.Version)
	}
	if !rec.Dirty {
		t.Fatal("edited record must be dirty")
	}
}

func TestVaultMarkDeleted(t *testing.T) {
	// Arrange
	v := NewVault()
	v.ApplyServer(Record{ID: "id-1", Type: "text", Payload: []byte("enc"), Version: 2, UpdatedAt: t0})

	// Act
	ok := v.MarkDeleted("id-1", t1)

	// Assert
	if !ok {
		t.Fatal("MarkDeleted = false, want true")
	}
	rec, _ := v.Get("id-1")
	if !rec.Deleted || !rec.Dirty {
		t.Fatalf("record = %+v, want deleted dirty tombstone", rec)
	}
	if rec.Payload != nil || rec.Metadata != nil {
		t.Fatal("tombstone must not keep ciphertext")
	}
	if len(v.List()) != 0 {
		t.Fatal("List must exclude deleted")
	}
	if v.MarkDeleted("id-1", t2) {
		t.Fatal("repeated MarkDeleted = true, want false")
	}
	if v.MarkDeleted("ghost", t2) {
		t.Fatal("MarkDeleted of unknown = true, want false")
	}
}

func TestVaultDirtyRecords(t *testing.T) {
	// Arrange
	v := NewVault()
	v.ApplyServer(Record{ID: "clean", Type: "text", Payload: []byte("enc"), Version: 1, UpdatedAt: t0})
	v.Put("dirty-new", "text", []byte("enc"), nil, t2)
	v.Put("dirty-old", "text", []byte("enc"), nil, t1)

	// Act
	dirty := v.DirtyRecords()

	// Assert
	if len(dirty) != 2 {
		t.Fatalf("DirtyRecords = %d, want 2", len(dirty))
	}
	if dirty[0].ID != "dirty-old" || dirty[1].ID != "dirty-new" {
		t.Fatalf("DirtyRecords order = %s, %s; want oldest first", dirty[0].ID, dirty[1].ID)
	}
}

func TestVaultApplyServer(t *testing.T) {
	// Arrange
	v := NewVault()
	v.Put("id-1", "text", []byte("local"), nil, t0)

	// Act
	v.ApplyServer(Record{ID: "id-1", Type: "text", Payload: []byte("server"), Version: 5, UpdatedAt: t1})

	// Assert
	rec, _ := v.Get("id-1")
	if rec.Dirty {
		t.Fatal("server record must be clean")
	}
	if string(rec.Payload) != "server" || rec.Version != 5 {
		t.Fatalf("record = %+v, want server state v5", rec)
	}
}

func TestVaultApplyServerDeletion(t *testing.T) {
	// Arrange
	v := NewVault()
	v.ApplyServer(Record{ID: "id-1", Type: "text", Payload: []byte("enc"), Version: 1, UpdatedAt: t0})

	// Act
	v.ApplyServer(Record{ID: "id-1", Deleted: true, Version: 2, UpdatedAt: t1})

	// Assert
	if _, ok := v.Get("id-1"); ok {
		t.Fatal("server-deleted record must be removed from cache")
	}
}

func TestVaultMarkSynced(t *testing.T) {
	// Arrange
	v := NewVault()
	v.Put("edited", "text", []byte("enc"), nil, t0)
	v.ApplyServer(Record{ID: "removed", Type: "text", Payload: []byte("enc"), Version: 1, UpdatedAt: t0})
	v.MarkDeleted("removed", t1)

	// Act
	v.MarkSynced("edited", 4)
	v.MarkSynced("removed", 2)
	v.MarkSynced("ghost", 1)

	// Assert
	edited, _ := v.Get("edited")
	if edited.Dirty || edited.Version != 4 {
		t.Fatalf("edited = %+v, want clean v4", edited)
	}
	if _, ok := v.Get("removed"); ok {
		t.Fatal("synced tombstone must be removed from cache")
	}
}
