package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	"github.com/a-aleesshin/gophkeeper/internal/access/usecase"
	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

type Server struct {
	pb.UnimplementedAccessServiceServer
	login   usecase.LoginHandler
	refresh usecase.RefreshHandler
	logout  usecase.LogoutHandler
}

func NewServer(login usecase.LoginHandler, refresh usecase.RefreshHandler, logout usecase.LogoutHandler) *Server {
	return &Server{login: login, refresh: refresh, logout: logout}
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.TokenPair, error) {
	result, err := s.login.Handle(ctx, usecase.LoginCommand{
		Login:    req.GetLogin(),
		Password: req.GetPassword(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return tokenPair(result), nil
}

func (s *Server) Refresh(ctx context.Context, req *pb.RefreshRequest) (*pb.TokenPair, error) {
	result, err := s.refresh.Handle(ctx, usecase.RefreshCommand{RefreshToken: req.GetRefreshToken()})
	if err != nil {
		return nil, mapError(err)
	}
	return tokenPair(result), nil
}

func (s *Server) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if err := s.logout.Handle(ctx, usecase.LogoutCommand{RefreshToken: req.GetRefreshToken()}); err != nil {
		return nil, mapError(err)
	}
	return &pb.LogoutResponse{}, nil
}

func tokenPair(result usecase.LoginResult) *pb.TokenPair {
	return &pb.TokenPair{
		AccessToken:      result.AccessToken,
		AccessExpiresAt:  timestamppb.New(result.AccessExpiresAt),
		RefreshToken:     result.RefreshToken,
		RefreshExpiresAt: timestamppb.New(result.RefreshExpiresAt),
	}
}

func mapError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrRefreshTokenNotFound),
		errors.Is(err, domain.ErrRefreshTokenExpired):
		return status.Error(codes.Unauthenticated, "authentication failed")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
