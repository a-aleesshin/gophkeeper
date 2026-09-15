package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
	googlegrpc "google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/reflection"

	"github.com/a-aleesshin/gophkeeper/internal/access"
	"github.com/a-aleesshin/gophkeeper/internal/identity"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/config"
	"github.com/a-aleesshin/gophkeeper/internal/platform/grpclog"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
	"github.com/a-aleesshin/gophkeeper/internal/platform/ratelimit"
	"github.com/a-aleesshin/gophkeeper/internal/vault"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

const shutdownTimeout = 15 * time.Second

func Run(ctx context.Context, cfg config.Config, log *slog.Logger) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("create pool: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}

	clk := clock.System{}
	ids := idgen.V7{}

	identityModule, err := identity.New(ctx, pool, clk, ids)
	if err != nil {
		return err
	}
	accessModule, err := access.New(pool, clk, ids, identityModule.API(), access.Config{
		JWTSecret:  []byte(cfg.JWTSecret),
		AccessTTL:  cfg.AccessTokenTTL,
		RefreshTTL: cfg.RefreshTokenTTL,
	})
	if err != nil {
		return err
	}
	vaultModule := vault.New(pool, clk)

	authLimiter := ratelimit.New(rate.Every(time.Second), 5)
	limitedMethods := map[string]bool{
		pb.IdentityService_Register_FullMethodName: true,
		pb.AccessService_Login_FullMethodName:      true,
		pb.AccessService_Refresh_FullMethodName:    true,
	}

	server := googlegrpc.NewServer(googlegrpc.ChainUnaryInterceptor(
		grpclog.UnaryInterceptor(log),
		ratelimit.UnaryInterceptor(authLimiter, limitedMethods),
		accessModule.AuthInterceptor(),
	))
	identityModule.RegisterGRPC(server)
	accessModule.RegisterGRPC(server)
	vaultModule.RegisterGRPC(server)
	reflection.Register(server)

	listener, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.GRPCAddress, err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()
	log.Info("server started", "address", cfg.GRPCAddress)

	select {
	case <-ctx.Done():
		shutdown(server, log)
		return nil
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	}
}

func shutdown(server *googlegrpc.Server, log *slog.Logger) {
	log.Info("shutting down", "timeout", shutdownTimeout)

	stopped := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		log.Info("server stopped gracefully")
	case <-time.After(shutdownTimeout):
		log.Warn("graceful stop timed out, forcing stop")
		server.Stop()
		<-stopped
	}
}
