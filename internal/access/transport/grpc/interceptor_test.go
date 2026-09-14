package grpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	"github.com/a-aleesshin/gophkeeper/internal/access/usecase"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/authctx"
)

type fakeTokenVerifier struct {
	userID vo.UserID
	err    error
}

func (f *fakeTokenVerifier) Verify(_ context.Context, _ string) (vo.UserID, error) {
	return f.userID, f.err
}

func mustUserID(t *testing.T) vo.UserID {
	t.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("UserIDFromUUID: %v", err)
	}
	return id
}

func callInfo(method string) *googlegrpc.UnaryServerInfo {
	return &googlegrpc.UnaryServerInfo{FullMethod: method}
}

func TestAuthInterceptorPublicMethodSkipsAuth(t *testing.T) {
	// Arrange
	interceptor := NewAuthInterceptor(
		usecase.NewAuthenticateHandler(&fakeTokenVerifier{err: domain.ErrInvalidAccessToken}),
		map[string]bool{"/gophkeeper.v1.AccessService/Login": true},
	)
	called := false

	// Act
	_, err := interceptor(context.Background(), nil, callInfo("/gophkeeper.v1.AccessService/Login"),
		func(ctx context.Context, _ any) (any, error) {
			called = true
			return nil, nil
		})

	// Assert
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	if !called {
		t.Fatal("handler was not called for public method")
	}
}

func TestAuthInterceptorValidToken(t *testing.T) {
	// Arrange
	userID := mustUserID(t)
	interceptor := NewAuthInterceptor(
		usecase.NewAuthenticateHandler(&fakeTokenVerifier{userID: userID}),
		map[string]bool{},
	)
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer valid-jwt"))
	var gotUserID vo.UserID

	// Act
	_, err := interceptor(ctx, nil, callInfo("/gophkeeper.v1.VaultService/GetSecret"),
		func(ctx context.Context, _ any) (any, error) {
			gotUserID, _ = authctx.UserIDFromContext(ctx)
			return nil, nil
		})

	// Assert
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	if gotUserID != userID {
		t.Fatalf("userID in context = %v, want %v", gotUserID, userID)
	}
}

func TestAuthInterceptorRejections(t *testing.T) {
	// Arrange
	tests := []struct {
		name     string
		ctx      context.Context
		verifier *fakeTokenVerifier
		wantMsg  string
	}{
		{
			name:     "no metadata",
			ctx:      context.Background(),
			verifier: &fakeTokenVerifier{},
			wantMsg:  "missing metadata",
		},
		{
			name:     "no authorization header",
			ctx:      metadata.NewIncomingContext(context.Background(), metadata.Pairs("other", "value")),
			verifier: &fakeTokenVerifier{},
			wantMsg:  "missing authorization",
		},
		{
			name:     "no bearer prefix",
			ctx:      metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "some-jwt")),
			verifier: &fakeTokenVerifier{},
			wantMsg:  "malformed authorization header",
		},
		{
			name:     "invalid token",
			ctx:      metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer bad")),
			verifier: &fakeTokenVerifier{err: domain.ErrInvalidAccessToken},
			wantMsg:  "invalid access token",
		},
		{
			name:     "expired token",
			ctx:      metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer old")),
			verifier: &fakeTokenVerifier{err: domain.ErrAccessTokenExpired},
			wantMsg:  "access token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor := NewAuthInterceptor(usecase.NewAuthenticateHandler(tt.verifier), map[string]bool{})

			// Act
			_, err := interceptor(tt.ctx, nil, callInfo("/gophkeeper.v1.VaultService/GetSecret"),
				func(context.Context, any) (any, error) {
					t.Fatal("handler must not be called")
					return nil, nil
				})

			// Assert
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("error is not a status: %v", err)
			}
			if st.Code() != codes.Unauthenticated {
				t.Fatalf("code = %v, want Unauthenticated", st.Code())
			}
			if st.Message() != tt.wantMsg {
				t.Fatalf("message = %q, want %q", st.Message(), tt.wantMsg)
			}
		})
	}
}
