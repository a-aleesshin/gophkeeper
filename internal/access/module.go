package access

import (
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	googlegrpc "google.golang.org/grpc"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/access/adapter"
	acpostgres "github.com/a-aleesshin/gophkeeper/internal/access/persistence/postgres"
	acgrpc "github.com/a-aleesshin/gophkeeper/internal/access/transport/grpc"
	"github.com/a-aleesshin/gophkeeper/internal/access/usecase"
	identityapi "github.com/a-aleesshin/gophkeeper/internal/identity/api"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
)

var (
	_ usecase.RefreshTokenCreator  = (*acpostgres.RefreshTokenRepository)(nil)
	_ usecase.RefreshTokenConsumer = (*acpostgres.RefreshTokenRepository)(nil)
	_ usecase.ExpiredTokensDeleter = (*acpostgres.RefreshTokenRepository)(nil)
	_ usecase.AccessTokenIssuer    = adapter.JWTManager{}
	_ usecase.AccessTokenVerifier  = adapter.JWTManager{}
	_ usecase.RefreshTokenCodec    = adapter.RefreshTokenCodec{}
	_ usecase.CredentialsVerifier  = adapter.IdentityCredentialsVerifier{}
)

type Config struct {
	JWTSecret  []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type Module struct {
	server      *acgrpc.Server
	interceptor googlegrpc.UnaryServerInterceptor
}

func New(pool *pgxpool.Pool, clk clock.Clock, ids idgen.Generator, identity *identityapi.Identity, cfg Config) (*Module, error) {
	jwtManager, err := adapter.NewJWTManager(cfg.JWTSecret, cfg.AccessTTL, clk)
	if err != nil {
		return nil, fmt.Errorf("access module: %w", err)
	}
	verifier := adapter.NewIdentityCredentialsVerifier(identity)
	codec := adapter.NewRefreshTokenCodec()
	repo := acpostgres.NewRefreshTokenRepository(pool)

	login := usecase.NewLoginHandler(verifier, jwtManager, codec, repo, repo, clk, ids, cfg.RefreshTTL)
	refresh := usecase.NewRefreshHandler(repo, jwtManager, codec, repo, clk, ids, cfg.RefreshTTL)
	logout := usecase.NewLogoutHandler(repo, codec)
	auth := usecase.NewAuthenticateHandler(jwtManager)

	publicMethods := map[string]bool{
		pb.IdentityService_Register_FullMethodName: true,
		pb.AccessService_Login_FullMethodName:      true,
		pb.AccessService_Refresh_FullMethodName:    true,
		pb.AccessService_Logout_FullMethodName:     true,
	}

	return &Module{
		server:      acgrpc.NewServer(login, refresh, logout),
		interceptor: acgrpc.NewAuthInterceptor(auth, publicMethods),
	}, nil
}

func (m *Module) RegisterGRPC(s googlegrpc.ServiceRegistrar) {
	pb.RegisterAccessServiceServer(s, m.server)
}

func (m *Module) AuthInterceptor() googlegrpc.UnaryServerInterceptor {
	return m.interceptor
}
