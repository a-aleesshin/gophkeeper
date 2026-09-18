package grpclog

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func UnaryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)

		code := status.Code(err)
		attrs := []any{
			"method", info.FullMethod,
			"code", code.String(),
			"duration", time.Since(start).String(),
		}

		switch {
		case err == nil:
			log.Info("rpc", attrs...)
		case code == codes.Internal || code == codes.Unknown:
			log.Error("rpc", append(attrs, "error", err)...)
		default:
			log.Warn("rpc", append(attrs, "error", err)...)
		}
		return resp, err
	}
}
