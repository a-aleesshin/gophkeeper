package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	googlegrpc "google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/reflection"

	"github.com/a-aleesshin/gophkeeper/internal/access"
	"github.com/a-aleesshin/gophkeeper/internal/identity"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/platform/config"
	"github.com/a-aleesshin/gophkeeper/internal/platform/idgen"
	platformpg "github.com/a-aleesshin/gophkeeper/internal/platform/postgres"
	"github.com/a-aleesshin/gophkeeper/internal/vault"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := platformpg.MigrateUp(cfg.DatabaseDSN); err != nil {
			return err
		}
		slog.Info("migrations applied")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	server := googlegrpc.NewServer(googlegrpc.ChainUnaryInterceptor(accessModule.AuthInterceptor()))
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
	slog.Info("server started", "address", cfg.GRPCAddress)

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		server.GracefulStop()
		return nil
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	}
}
