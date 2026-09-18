package transport

import (
	"context"
	"fmt"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/client/session"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
)

const maxMessageSize = 64 << 20

type Client struct {
	conn     *googlegrpc.ClientConn
	Identity pb.IdentityServiceClient
	Access   pb.AccessServiceClient
	Vault    pb.VaultServiceClient
	Tokens   *TokenManager
}

func New(addr string, store *session.Store, clk clock.Clock) (*Client, error) {
	tokens := NewTokenManager(store, clk)

	conn, err := googlegrpc.NewClient(addr,
		googlegrpc.WithTransportCredentials(insecure.NewCredentials()),
		googlegrpc.WithChainUnaryInterceptor(AuthInterceptor(tokens)),
		googlegrpc.WithDefaultCallOptions(googlegrpc.MaxCallRecvMsgSize(maxMessageSize)),
	)

	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}

	access := pb.NewAccessServiceClient(conn)
	tokens.SetRefresher(grpcRefresher{access: access})

	return &Client{
		conn:     conn,
		Identity: pb.NewIdentityServiceClient(conn),
		Access:   access,
		Vault:    pb.NewVaultServiceClient(conn),
		Tokens:   tokens,
	}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

type grpcRefresher struct {
	access pb.AccessServiceClient
}

func (r grpcRefresher) Refresh(ctx context.Context, refreshToken string) (*pb.TokenPair, error) {
	return r.access.Refresh(ctx, &pb.RefreshRequest{RefreshToken: refreshToken})
}
