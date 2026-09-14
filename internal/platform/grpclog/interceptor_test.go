package grpclog

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type captureHandler struct {
	records []slog.Record
}

func (c *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	c.records = append(c.records, r)
	return nil
}
func (c *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *captureHandler) WithGroup(string) slog.Handler      { return c }

func TestUnaryInterceptorLogLevels(t *testing.T) {
	// Arrange
	tests := []struct {
		name      string
		err       error
		wantLevel slog.Level
	}{
		{name: "success", err: nil, wantLevel: slog.LevelInfo},
		{name: "client error", err: status.Error(codes.NotFound, "not found"), wantLevel: slog.LevelWarn},
		{name: "unauthenticated", err: status.Error(codes.Unauthenticated, "no token"), wantLevel: slog.LevelWarn},
		{name: "internal error", err: status.Error(codes.Internal, "boom"), wantLevel: slog.LevelError},
		{name: "unknown error", err: errors.New("raw error"), wantLevel: slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture := &captureHandler{}
			interceptor := UnaryInterceptor(slog.New(capture))

			// Act
			_, _ = interceptor(context.Background(), nil,
				&grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.VaultService/GetSecret"},
				func(context.Context, any) (any, error) { return nil, tt.err })

			// Assert
			if len(capture.records) != 1 {
				t.Fatalf("records = %d, want 1", len(capture.records))
			}
			if capture.records[0].Level != tt.wantLevel {
				t.Fatalf("level = %v, want %v", capture.records[0].Level, tt.wantLevel)
			}
		})
	}
}

func TestUnaryInterceptorDoesNotLogPayload(t *testing.T) {
	// Arrange
	capture := &captureHandler{}
	interceptor := UnaryInterceptor(slog.New(capture))
	secretPayload := struct{ Password string }{Password: "super-secret"}

	// Act
	_, _ = interceptor(context.Background(), secretPayload,
		&grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.AccessService/Login"},
		func(context.Context, any) (any, error) { return nil, nil })

	// Assert
	found := false
	capture.records[0].Attrs(func(a slog.Attr) bool {
		if a.Value.String() == "super-secret" {
			found = true
		}
		return true
	})
	if found {
		t.Fatal("interceptor logged request payload")
	}
}
