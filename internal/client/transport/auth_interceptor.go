package transport

import (
	"context"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

var publicMethods = map[string]bool{
	pb.IdentityService_Register_FullMethodName: true,
	pb.AccessService_Login_FullMethodName:      true,
	pb.AccessService_Refresh_FullMethodName:    true,
	pb.AccessService_Logout_FullMethodName:     true,
}

func AuthInterceptor(tokens TokenProvider) googlegrpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *googlegrpc.ClientConn, invoker googlegrpc.UnaryInvoker, opts ...googlegrpc.CallOption) error {
		if publicMethods[method] {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		token, err := tokens.Token(ctx)

		if err != nil {
			return err
		}
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)

		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
