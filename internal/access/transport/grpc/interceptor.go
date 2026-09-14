package grpc

import (
	"context"
	"errors"
	"strings"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	"github.com/a-aleesshin/gophkeeper/internal/access/usecase"
	"github.com/a-aleesshin/gophkeeper/internal/platform/authctx"
)

const bearerPrefix = "Bearer "

func NewAuthInterceptor(auth usecase.AuthenticateHandler, publicMethods map[string]bool) googlegrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *googlegrpc.UnaryServerInfo, handler googlegrpc.UnaryHandler) (any, error) {
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		token, err := bearerToken(ctx)
		if err != nil {
			return nil, err
		}

		result, err := auth.Handle(ctx, usecase.AuthenticateCommand{AccessToken: token})
		if err != nil {
			if errors.Is(err, domain.ErrAccessTokenExpired) {
				return nil, status.Error(codes.Unauthenticated, "access token expired")
			}
			return nil, status.Error(codes.Unauthenticated, "invalid access token")
		}

		return handler(authctx.WithUserID(ctx, result.UserID), req)
	}
}

func bearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization")
	}
	token := strings.TrimPrefix(values[0], bearerPrefix)
	if token == "" || token == values[0] {
		return "", status.Error(codes.Unauthenticated, "malformed authorization header")
	}
	return token, nil
}
