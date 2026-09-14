package transport

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/client/session"
)

type fixedClock struct {
	now time.Time
}

func (f fixedClock) Now() time.Time { return f.now }

type fakeRefresher struct {
	pair  *pb.TokenPair
	err   error
	calls int
}

func (f *fakeRefresher) Refresh(_ context.Context, _ string) (*pb.TokenPair, error) {
	f.calls++
	return f.pair, f.err
}

func setupManager(t *testing.T, sess *session.Session, now time.Time, refresher *fakeRefresher) (*TokenManager, *session.Store) {
	t.Helper()
	store := session.NewStore(filepath.Join(t.TempDir(), "session.json"))
	if sess != nil {
		if err := store.Save(*sess); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	m := NewTokenManager(store, fixedClock{now: now})
	if refresher != nil {
		m.SetRefresher(refresher)
	}
	return m, store
}

func TestTokenManagerFreshToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	refresher := &fakeRefresher{}
	m, _ := setupManager(t, &session.Session{
		AccessToken:     "fresh-jwt",
		AccessExpiresAt: now.Add(10 * time.Minute),
		RefreshToken:    "id.secret",
	}, now, refresher)

	// Act
	token, err := m.Token(context.Background())

	// Assert
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != "fresh-jwt" {
		t.Fatalf("token = %q, want fresh-jwt", token)
	}
	if refresher.calls != 0 {
		t.Fatal("refresher must not be called for fresh token")
	}
}

func TestTokenManagerRefreshesStaleToken(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	refresher := &fakeRefresher{pair: &pb.TokenPair{
		AccessToken:      "new-jwt",
		AccessExpiresAt:  timestamppb.New(now.Add(15 * time.Minute)),
		RefreshToken:     "new-id.new-secret",
		RefreshExpiresAt: timestamppb.New(now.Add(720 * time.Hour)),
	}}
	m, store := setupManager(t, &session.Session{
		Login:           "alice",
		AccessToken:     "stale-jwt",
		AccessExpiresAt: now.Add(10 * time.Second),
		RefreshToken:    "old-id.old-secret",
		EncryptionKey:   []byte{1, 2, 3},
	}, now, refresher)

	// Act
	token, err := m.Token(context.Background())

	// Assert
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if token != "new-jwt" {
		t.Fatalf("token = %q, want new-jwt", token)
	}
	if refresher.calls != 1 {
		t.Fatalf("refresher calls = %d, want 1", refresher.calls)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.AccessToken != "new-jwt" || saved.RefreshToken != "new-id.new-secret" {
		t.Fatalf("session not rotated: %+v", saved)
	}
	if saved.Login != "alice" || string(saved.EncryptionKey) != string([]byte{1, 2, 3}) {
		t.Fatal("refresh must preserve login and encryption key")
	}
}

func TestTokenManagerSessionExpired(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	refresher := &fakeRefresher{err: status.Error(codes.Unauthenticated, "authentication failed")}
	m, store := setupManager(t, &session.Session{
		AccessToken:     "stale-jwt",
		AccessExpiresAt: now.Add(-time.Minute),
		RefreshToken:    "revoked-id.secret",
	}, now, refresher)

	// Act
	_, err := m.Token(context.Background())

	// Assert
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Token error = %v, want ErrSessionExpired", err)
	}
	if _, err := store.Load(); !errors.Is(err, session.ErrNoSession) {
		t.Fatal("session must be cleared after failed refresh")
	}
}

func TestTokenManagerNoSession(t *testing.T) {
	// Arrange
	m, _ := setupManager(t, nil, time.Now(), &fakeRefresher{})

	// Act
	_, err := m.Token(context.Background())

	// Assert
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("Token error = %v, want ErrNotAuthenticated", err)
	}
}

func TestTokenManagerInfrastructureErrorKeepsSession(t *testing.T) {
	// Arrange
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	refresher := &fakeRefresher{err: status.Error(codes.Unavailable, "server down")}
	m, store := setupManager(t, &session.Session{
		AccessToken:     "stale-jwt",
		AccessExpiresAt: now.Add(-time.Minute),
		RefreshToken:    "id.secret",
	}, now, refresher)

	// Act
	_, err := m.Token(context.Background())

	// Assert
	if err == nil || errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Token error = %v, want wrapped infrastructure error", err)
	}
	if _, loadErr := store.Load(); loadErr != nil {
		t.Fatal("session must be kept when server is unavailable")
	}
}
