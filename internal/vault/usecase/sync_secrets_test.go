package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

func syncHandler(store *fakeStore, tx *fakeTxRunner, now time.Time) SyncSecretsHandler {
	return NewSyncSecretsHandler(store, store, store, store, tx, fixedClock{now: now})
}

func TestSyncPushNewSecret(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	owner := mustOwnerID(t)
	store := newFakeStore()
	tx := &fakeTxRunner{}
	newID := uuid.Must(uuid.NewV7()).String()
	cmd := SyncSecretsCommand{
		OwnerID: owner,
		Since:   now.Add(-time.Hour),
		Items: []SyncItem{{
			SecretID: newID,
			Type:     "text",
			Payload:  []byte("ciphertext"),
			Metadata: []byte("meta"),
		}},
	}

	// Act
	got, err := syncHandler(store, tx, now).Handle(context.Background(), cmd)

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if tx.calls != 1 {
		t.Fatalf("tx calls = %d, want 1", tx.calls)
	}

	if len(got.Applied) != 1 || got.Applied[0].Version != 1 {
		t.Fatalf("Applied = %+v, want one item with version 1", got.Applied)
	}

	if len(got.Conflicts) != 0 || len(got.Changes) != 0 {
		t.Fatalf("unexpected conflicts/changes: %+v / %+v", got.Conflicts, got.Changes)
	}

	if !got.Cursor.Equal(now) {
		t.Fatalf("Cursor = %v, want %v", got.Cursor, now)
	}

	if _, ok := store.secrets[newID]; !ok {
		t.Fatal("secret not stored")
	}
}

func TestSyncPushUpdateAndDelete(t *testing.T) {
	// Arrange
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)
	owner := mustOwnerID(t)
	store := newFakeStore()
	toUpdate := mustSecret(t, owner, base)
	toDelete := mustSecret(t, owner, base)
	store.secrets[toUpdate.ID().String()] = toUpdate
	store.secrets[toDelete.ID().String()] = toDelete

	cmd := SyncSecretsCommand{
		OwnerID: owner,
		Since:   base,
		Items: []SyncItem{
			{SecretID: toUpdate.ID().String(), Type: "credentials", Payload: []byte("v2"), BaseVersion: 1},
			{SecretID: toDelete.ID().String(), Deleted: true, BaseVersion: 1},
		},
	}

	// Act
	got, err := syncHandler(store, &fakeTxRunner{}, now).Handle(context.Background(), cmd)

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(got.Applied) != 2 {
		t.Fatalf("Applied = %+v, want 2 items", got.Applied)
	}

	for _, a := range got.Applied {
		if a.Version != 2 {
			t.Fatalf("applied version = %d, want 2", a.Version)
		}
	}

	if len(got.Changes) != 0 {
		t.Fatalf("own pushes echoed back as changes: %+v", got.Changes)
	}

	if !store.secrets[toDelete.ID().String()].IsDeleted() {
		t.Fatal("tombstone not stored")
	}

	if string(store.secrets[toUpdate.ID().String()].Payload().Bytes()) != "v2" {
		t.Fatal("update not stored")
	}
}

func TestSyncConflictReturnsServerState(t *testing.T) {
	// Arrange
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)
	owner := mustOwnerID(t)
	store := newFakeStore()
	s := mustSecret(t, owner, base)
	serverSide, err := s.Update(mustPayload(t, []byte("server-v2")), domain.Metadata{}, 1, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	store.secrets[s.ID().String()] = serverSide

	cmd := SyncSecretsCommand{
		OwnerID: owner,
		Since:   base,
		Items:   []SyncItem{{SecretID: s.ID().String(), Type: "credentials", Payload: []byte("client-v2"), BaseVersion: 1}},
	}

	// Act
	got, err := syncHandler(store, &fakeTxRunner{}, now).Handle(context.Background(), cmd)

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(got.Applied) != 0 {
		t.Fatalf("Applied = %+v, want empty", got.Applied)
	}

	if len(got.Conflicts) != 1 {
		t.Fatalf("Conflicts = %+v, want 1", got.Conflicts)
	}

	c := got.Conflicts[0]
	if c.ServerVersion != 2 || string(c.ServerPayload) != "server-v2" {
		t.Fatalf("conflict = %+v, want server state v2", c)
	}

	if string(store.secrets[s.ID().String()].Payload().Bytes()) != "server-v2" {
		t.Fatal("conflict must not overwrite server state")
	}

	if len(got.Changes) != 0 {
		t.Fatalf("conflicting id echoed in changes: %+v", got.Changes)
	}
}

func TestSyncPullsServerChanges(t *testing.T) {
	// Arrange
	base := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	now := base.Add(time.Hour)
	owner := mustOwnerID(t)
	store := newFakeStore()
	changed := mustSecret(t, owner, base.Add(time.Minute))
	unchanged := mustSecret(t, owner, base.Add(-time.Hour))
	foreign := mustSecret(t, mustOwnerID(t), base.Add(time.Minute))
	store.secrets[changed.ID().String()] = changed
	store.secrets[unchanged.ID().String()] = unchanged
	store.secrets[foreign.ID().String()] = foreign

	// Act
	got, err := syncHandler(store, &fakeTxRunner{}, now).Handle(context.Background(), SyncSecretsCommand{OwnerID: owner, Since: base})

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(got.Changes) != 1 {
		t.Fatalf("Changes = %+v, want exactly changed secret", got.Changes)
	}

	if got.Changes[0].SecretID != changed.ID().String() {
		t.Fatalf("Changes[0] = %s, want %s", got.Changes[0].SecretID, changed.ID())
	}
}

func TestSyncDeleteOfUnknownIsNoop(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	owner := mustOwnerID(t)
	store := newFakeStore()
	cmd := SyncSecretsCommand{
		OwnerID: owner,
		Since:   now.Add(-time.Hour),
		Items:   []SyncItem{{SecretID: uuid.Must(uuid.NewV7()).String(), Deleted: true, BaseVersion: 3}},
	}

	// Act
	got, err := syncHandler(store, &fakeTxRunner{}, now).Handle(context.Background(), cmd)

	// Assert
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(got.Applied) != 1 || got.Applied[0].Version != 0 {
		t.Fatalf("Applied = %+v, want one noop item with version 0", got.Applied)
	}

	if len(store.secrets) != 0 {
		t.Fatal("noop delete created a record")
	}
}

func mustPayload(t *testing.T, b []byte) domain.Payload {
	t.Helper()

	p, err := domain.NewPayload(b)
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}
	return p
}
