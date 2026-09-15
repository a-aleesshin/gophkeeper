package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
	"github.com/a-aleesshin/gophkeeper/internal/identity/usecase"
	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

type Server struct {
	pb.UnimplementedIdentityServiceServer
	register usecase.RegisterUserHandler
}

func NewServer(register usecase.RegisterUserHandler) *Server {
	return &Server{register: register}
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	result, err := s.register.Handle(ctx, usecase.RegisterUserCommand{
		Login:    req.GetLogin(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &pb.RegisterResponse{UserId: result.UserID}, nil
}

func mapError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	case errors.Is(err, domain.ErrInvalidLogin), errors.Is(err, domain.ErrWeakPassword):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrLoginTaken):
		return status.Error(codes.AlreadyExists, domain.ErrLoginTaken.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
