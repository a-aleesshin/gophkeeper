package vault

import (
	"github.com/jackc/pgx/v5/pgxpool"
	googlegrpc "google.golang.org/grpc"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	platformpg "github.com/a-aleesshin/gophkeeper/internal/platform/postgres"
	vpostgres "github.com/a-aleesshin/gophkeeper/internal/vault/persistence/postgres"
	vgrpc "github.com/a-aleesshin/gophkeeper/internal/vault/transport/grpc"
	"github.com/a-aleesshin/gophkeeper/internal/vault/usecase"
)

var (
	_ usecase.SecretCreator        = (*vpostgres.SecretRepository)(nil)
	_ usecase.SecretProvider       = (*vpostgres.SecretRepository)(nil)
	_ usecase.SecretSaver          = (*vpostgres.SecretRepository)(nil)
	_ usecase.SecretLister         = (*vpostgres.SecretRepository)(nil)
	_ usecase.ChangedSecretsLister = (*vpostgres.SecretRepository)(nil)
	_ usecase.TxRunner             = (*platformpg.TxRunner)(nil)
)

type Module struct {
	server *vgrpc.Server
}

func New(pool *pgxpool.Pool, clk clock.Clock) *Module {
	repo := vpostgres.NewSecretRepository(pool)
	tx := platformpg.NewTxRunner(pool)

	return &Module{
		server: vgrpc.NewServer(
			usecase.NewCreateSecretHandler(repo, clk),
			usecase.NewGetSecretHandler(repo),
			usecase.NewListSecretsHandler(repo),
			usecase.NewUpdateSecretHandler(repo, repo, clk),
			usecase.NewDeleteSecretHandler(repo, repo, clk),
			usecase.NewSyncSecretsHandler(repo, repo, repo, repo, tx, clk),
		),
	}
}

func (m *Module) RegisterGRPC(s googlegrpc.ServiceRegistrar) {
	pb.RegisterVaultServiceServer(s, m.server)
}
