package transport

import (
	"context"
	"errors"
	"testing"

	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

type staticProvider struct {
	token string
	err   error
}

func (p staticProvider) Token(context.Context) (string, error) { return p.token, p.err }

func captureInvoker(captured *metadata.MD) googlegrpc.UnaryInvoker {
	return func(ctx context.Context, _ string, _, _ any, _ *googlegrpc.ClientConn, _ ...googlegrpc.CallOption) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		*captured = md
		return nil
	}
}

func TestAuthInterceptorAttachesToken(t *testing.T) {
	// Arrange
	interceptor := AuthInterceptor(staticProvider{token: "jwt-token"})
	var captured metadata.MD

	// Act
	err := interceptor(context.Background(), pb.VaultService_GetSecret_FullMethodName,
		nil, nil, nil, captureInvoker(&captured))

	// Assert
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	values := captured.Get("authorization")
	if len(values) != 1 || values[0] != "Bearer jwt-token" {
		t.Fatalf("authorization = %v, want [Bearer jwt-token]", values)
	}
}

func TestAuthInterceptorSkipsPublicMethods(t *testing.T) {
	// Arrange
	interceptor := AuthInterceptor(staticProvider{err: errors.New("must not be called")})

	for _, method := range []string{
		pb.IdentityService_Register_FullMethodName,
		pb.AccessService_Login_FullMethodName,
		pb.AccessService_Refresh_FullMethodName,
		pb.AccessService_Logout_FullMethodName,
	} {
		var captured metadata.MD

		// Act
		err := interceptor(context.Background(), method, nil, nil, nil, captureInvoker(&captured))

		// Assert
		if err != nil {
			t.Fatalf("interceptor(%s): %v", method, err)
		}
		if len(captured.Get("authorization")) != 0 {
			t.Fatalf("public method %s got authorization header", method)
		}
	}
}

func TestAuthInterceptorProviderError(t *testing.T) {
	// Arrange
	providerErr := errors.New("not authenticated")
	interceptor := AuthInterceptor(staticProvider{err: providerErr})

	// Act
	err := interceptor(context.Background(), pb.VaultService_ListSecrets_FullMethodName,
		nil, nil, nil, captureInvoker(&metadata.MD{}))

	// Assert
	if !errors.Is(err, providerErr) {
		t.Fatalf("interceptor error = %v, want %v", err, providerErr)
	}
}
