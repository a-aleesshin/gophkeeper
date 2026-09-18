package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/a-aleesshin/gophkeeper/internal/app"
	"github.com/a-aleesshin/gophkeeper/internal/platform/config"
	"github.com/a-aleesshin/gophkeeper/internal/platform/logger"
	platformpg "github.com/a-aleesshin/gophkeeper/internal/platform/postgres"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := logger.New(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	if flag.Arg(0) == "migrate" {
		if err := platformpg.MigrateUp(cfg.DatabaseDSN); err != nil {
			return err
		}
		log.Info("migrations applied")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx, cfg, log)
}
