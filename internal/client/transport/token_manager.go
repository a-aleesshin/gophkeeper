package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/client/session"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
)

const expirySkew = 30 * time.Second

var (
	ErrNotAuthenticated = errors.New("not authenticated, run login first")
	ErrSessionExpired   = errors.New("session expired, run login again")
)

type TokenRefresher interface {
	Refresh(ctx context.Context, refreshToken string) (*pb.TokenPair, error)
}

type TokenManager struct {
	store     *session.Store
	clock     clock.Clock
	mu        sync.Mutex
	refresher TokenRefresher
}

func NewTokenManager(store *session.Store, clk clock.Clock) *TokenManager {
	return &TokenManager{store: store, clock: clk}
}

func (m *TokenManager) SetRefresher(r TokenRefresher) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresher = r
}

func (m *TokenManager) Token(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	unlock, err := m.store.Lock()
	if err != nil {
		return "", err
	}
	defer unlock()

	sess, err := m.store.Load()
	if err != nil {
		if errors.Is(err, session.ErrNoSession) {
			return "", ErrNotAuthenticated
		}

		return "", err
	}

	if m.clock.Now().Add(expirySkew).Before(sess.AccessExpiresAt) {
		return sess.AccessToken, nil
	}

	if m.refresher == nil {
		return "", errors.New("token refresher is not configured")
	}
	pair, err := m.refresher.Refresh(ctx, sess.RefreshToken)

	if err != nil {
		if status.Code(err) == codes.Unauthenticated {
			_ = m.store.Clear()

			return "", ErrSessionExpired
		}

		return "", fmt.Errorf("refresh session: %w", err)
	}

	sess.AccessToken = pair.GetAccessToken()
	sess.AccessExpiresAt = pair.GetAccessExpiresAt().AsTime()
	sess.RefreshToken = pair.GetRefreshToken()
	if err := m.store.Save(sess); err != nil {
		return "", fmt.Errorf("save session: %w", err)
	}

	return sess.AccessToken, nil
}
