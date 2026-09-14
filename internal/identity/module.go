package identity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	googlegrpc "google.golang.org/grpc"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/identity/adapter"
	"github.com/a-aleesshin/gophkeeper/internal/identity/api"
	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	idpostgres "github.com/a-aleesshin/gophkeeper/internal/identity/persistence/postgres"
	idgrpc "github.com/a-aleesshin/gophkeeper/internal/identity/transport/grpc"
	"github.com/a-aleesshin/gophkeeper/internal/identity/usecase"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
)

var (
	_ usecase.UserCreator         = (*idpostgres.UserRepository)(nil)
	_ usecase.UserByLoginProvider = (*idpostgres.UserRepository)(nil)
	_ usecase.PasswordHasher      = adapter.Argon2Hasher{}
	_ usecase.PasswordVerifier    = adapter.Argon2Hasher{}
)

type Module struct {
	api    *api.Identity
	server *idgrpc.Server
}

func New(ctx context.Context, pool *pgxpool.Pool, clk clock.Clock, ids idgen.Generator) (*Module, error) {
	repo := idpostgres.NewUserRepository(pool)
	hasher := adapter.NewArgon2Hasher()

	dummyHash, err := makeDummyHash(ctx, hasher)
	if err != nil {
		return nil, fmt.Errorf("identity module: %w", err)
	}

	register := usecase.NewRegisterUserHandler(repo, hasher, clk, ids)
	verify := usecase.NewVerifyCredentialsHandler(repo, hasher, dummyHash)

	return &Module{
		api:    api.NewIdentity(verify),
		server: idgrpc.NewServer(register),
	}, nil
}

func (m *Module) API() *api.Identity { return m.api }

func (m *Module) RegisterGRPC(s googlegrpc.ServiceRegistrar) {
	pb.RegisterIdentityServiceServer(s, m.server)
}

func makeDummyHash(ctx context.Context, hasher adapter.Argon2Hasher) (domain.PasswordHash, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return domain.PasswordHash{}, fmt.Errorf("dummy password: %w", err)
	}
	password, err := domain.NewPassword(hex.EncodeToString(raw))
	if err != nil {
		return domain.PasswordHash{}, err
	}
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return domain.PasswordHash{}, fmt.Errorf("dummy hash: %w", err)
	}
	return hash, nil
}
