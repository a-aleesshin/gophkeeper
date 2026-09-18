package grpc

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

func TestMapError(t *testing.T) {
	// Arrange
	tests := []struct {
		name string
		err  error
		want codes.Code
	}{
		{name: "invalid id", err: domain.ErrInvalidSecretID, want: codes.InvalidArgument},
		{name: "unknown type", err: domain.ErrUnknownSecretType, want: codes.InvalidArgument},
		{name: "empty payload", err: domain.ErrEmptyPayload, want: codes.InvalidArgument},
		{name: "payload too large", err: domain.ErrPayloadTooLarge, want: codes.InvalidArgument},
		{name: "metadata too large", err: domain.ErrMetadataTooLarge, want: codes.InvalidArgument},
		{name: "not found", err: domain.ErrSecretNotFound, want: codes.NotFound},
		{name: "deleted", err: domain.ErrSecretDeleted, want: codes.NotFound},
		{name: "version conflict", err: domain.ErrVersionConflict, want: codes.FailedPrecondition},
		{name: "already exists", err: domain.ErrSecretAlreadyExists, want: codes.AlreadyExists},
		{name: "invalid user", err: vo.ErrInvalidUserID, want: codes.Unauthenticated},
		{name: "wrapped domain error", err: errors.Join(errors.New("get secret"), domain.ErrSecretNotFound), want: codes.NotFound},
		{name: "unknown error", err: errors.New("pgx: connection refused"), want: codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got := mapError(tt.err)

			// Assert
			st, ok := status.FromError(got)
			if !ok {
				t.Fatalf("mapError result is not a status: %v", got)
			}
			if st.Code() != tt.want {
				t.Fatalf("code = %v, want %v", st.Code(), tt.want)
			}
		})
	}
}

func TestMapErrorHidesInternals(t *testing.T) {
	// Arrange
	leaky := errors.New("pgx: password authentication failed for user gophkeeper")

	// Act
	got := mapError(leaky)

	// Assert
	st, _ := status.FromError(got)
	if st.Message() != "internal error" {
		t.Fatalf("internal error leaked details: %q", st.Message())
	}
}

func TestSecretTypeConversion(t *testing.T) {
	// Arrange
	tests := []struct {
		proto pb.SecretType
		str   string
	}{
		{proto: pb.SecretType_SECRET_TYPE_CREDENTIALS, str: "credentials"},
		{proto: pb.SecretType_SECRET_TYPE_TEXT, str: "text"},
		{proto: pb.SecretType_SECRET_TYPE_BINARY, str: "binary"},
		{proto: pb.SecretType_SECRET_TYPE_CARD, str: "card"},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			// Act
			gotStr := typeFromProto(tt.proto)
			gotProto := typeToProto(tt.str)

			// Assert
			if gotStr != tt.str {
				t.Fatalf("typeFromProto = %q, want %q", gotStr, tt.str)
			}
			if gotProto != tt.proto {
				t.Fatalf("typeToProto = %v, want %v", gotProto, tt.proto)
			}
		})
	}
}

func TestSecretTypeConversionUnknown(t *testing.T) {
	// Act + Assert
	if got := typeFromProto(pb.SecretType_SECRET_TYPE_UNSPECIFIED); got != "" {
		t.Fatalf("typeFromProto(UNSPECIFIED) = %q, want empty", got)
	}
	if got := typeToProto("totp"); got != pb.SecretType_SECRET_TYPE_UNSPECIFIED {
		t.Fatalf("typeToProto(totp) = %v, want UNSPECIFIED", got)
	}
}

func TestOwnerFromContextMissing(t *testing.T) {
	// Act
	_, err := ownerFromContext(context.Background())

	// Assert
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Fatalf("error = %v, want Unauthenticated status", err)
	}
}
