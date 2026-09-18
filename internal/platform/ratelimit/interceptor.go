package ratelimit

import (
	"context"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func UnaryInterceptor(limiter *Limiter, methods map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !methods[info.FullMethod] {
			return handler(ctx, req)
		}
		if !limiter.Allow(peerKey(ctx)) {
			return nil, status.Error(codes.ResourceExhausted, "too many requests")
		}
		return handler(ctx, req)
	}
}

func peerKey(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
