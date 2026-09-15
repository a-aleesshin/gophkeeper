package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/authctx"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
	"github.com/a-aleesshin/gophkeeper/internal/vault/usecase"
	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
)

type Server struct {
	pb.UnimplementedVaultServiceServer
	create usecase.CreateSecretHandler
	get    usecase.GetSecretHandler
	list   usecase.ListSecretsHandler
	update usecase.UpdateSecretHandler
	delete usecase.DeleteSecretHandler
	sync   usecase.SyncSecretsHandler
}

func NewServer(
	create usecase.CreateSecretHandler,
	get usecase.GetSecretHandler,
	list usecase.ListSecretsHandler,
	update usecase.UpdateSecretHandler,
	delete usecase.DeleteSecretHandler,
	sync usecase.SyncSecretsHandler,
) *Server {
	return &Server{create: create, get: get, list: list, update: update, delete: delete, sync: sync}
}

func (s *Server) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretResponse, error) {
	ownerID, err := ownerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.create.Handle(ctx, usecase.CreateSecretCommand{
		OwnerID:  ownerID,
		SecretID: req.GetSecretId(),
		Type:     typeFromProto(req.GetType()),
		Payload:  req.GetPayload(),
		Metadata: req.GetMetadata(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &pb.CreateSecretResponse{Version: result.Version}, nil
}

func (s *Server) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	ownerID, err := ownerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.get.Handle(ctx, usecase.GetSecretQuery{OwnerID: ownerID, SecretID: req.GetSecretId()})
	if err != nil {
		return nil, mapError(err)
	}
	return &pb.GetSecretResponse{
		SecretId:  result.SecretID,
		Type:      typeToProto(result.Type),
		Payload:   result.Payload,
		Metadata:  result.Metadata,
		Version:   result.Version,
		CreatedAt: timestamppb.New(result.CreatedAt),
		UpdatedAt: timestamppb.New(result.UpdatedAt),
	}, nil
}

func (s *Server) ListSecrets(ctx context.Context, _ *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	ownerID, err := ownerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.list.Handle(ctx, usecase.ListSecretsQuery{OwnerID: ownerID})
	if err != nil {
		return nil, mapError(err)
	}
	items := make([]*pb.SecretHeader, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, &pb.SecretHeader{
			SecretId:  item.SecretID,
			Type:      typeToProto(item.Type),
			Metadata:  item.Metadata,
			Version:   item.Version,
			UpdatedAt: timestamppb.New(item.UpdatedAt),
		})
	}
	return &pb.ListSecretsResponse{Items: items}, nil
}

func (s *Server) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.UpdateSecretResponse, error) {
	ownerID, err := ownerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.update.Handle(ctx, usecase.UpdateSecretCommand{
		OwnerID:  ownerID,
		SecretID: req.GetSecretId(),
		Payload:  req.GetPayload(),
		Metadata: req.GetMetadata(),
		Version:  req.GetVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &pb.UpdateSecretResponse{Version: result.Version}, nil
}

func (s *Server) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	ownerID, err := ownerFromContext(ctx)
	if err != nil {
		return nil, err
	}
	result, err := s.delete.Handle(ctx, usecase.DeleteSecretCommand{
		OwnerID:  ownerID,
		SecretID: req.GetSecretId(),
		Version:  req.GetVersion(),
	})
	if err != nil {
		return nil, mapError(err)
	}
	return &pb.DeleteSecretResponse{Version: result.Version}, nil
}

func (s *Server) SyncSecrets(ctx context.Context, req *pb.SyncSecretsRequest) (*pb.SyncSecretsResponse, error) {
	ownerID, err := ownerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	items := make([]usecase.SyncItem, 0, len(req.GetItems()))
	for _, item := range req.GetItems() {
		items = append(items, usecase.SyncItem{
			SecretID:    item.GetSecretId(),
			Type:        typeFromProto(item.GetType()),
			Payload:     item.GetPayload(),
			Metadata:    item.GetMetadata(),
			Deleted:     item.GetDeleted(),
			BaseVersion: item.GetBaseVersion(),
		})
	}

	result, err := s.sync.Handle(ctx, usecase.SyncSecretsCommand{
		OwnerID: ownerID,
		Since:   req.GetSince().AsTime(),
		Items:   items,
	})
	if err != nil {
		return nil, mapError(err)
	}

	applied := make([]*pb.SyncApplied, 0, len(result.Applied))
	for _, a := range result.Applied {
		applied = append(applied, &pb.SyncApplied{SecretId: a.SecretID, Version: a.Version})
	}
	conflicts := make([]*pb.SyncConflict, 0, len(result.Conflicts))
	for _, c := range result.Conflicts {
		conflicts = append(conflicts, &pb.SyncConflict{
			SecretId:       c.SecretID,
			ServerType:     typeToProto(c.ServerType),
			ServerPayload:  c.ServerPayload,
			ServerMetadata: c.ServerMetadata,
			ServerDeleted:  c.ServerDeleted,
			ServerVersion:  c.ServerVersion,
			UpdatedAt:      timestamppb.New(c.UpdatedAt),
		})
	}
	changes := make([]*pb.SyncChange, 0, len(result.Changes))
	for _, c := range result.Changes {
		changes = append(changes, &pb.SyncChange{
			SecretId:  c.SecretID,
			Type:      typeToProto(c.Type),
			Payload:   c.Payload,
			Metadata:  c.Metadata,
			Deleted:   c.Deleted,
			Version:   c.Version,
			UpdatedAt: timestamppb.New(c.UpdatedAt),
		})
	}

	return &pb.SyncSecretsResponse{
		Applied:   applied,
		Conflicts: conflicts,
		Changes:   changes,
		Cursor:    timestamppb.New(result.Cursor),
	}, nil
}

func ownerFromContext(ctx context.Context) (vo.UserID, error) {
	ownerID, ok := authctx.UserIDFromContext(ctx)
	if !ok {
		return vo.UserID{}, status.Error(codes.Unauthenticated, "missing authentication")
	}
	return ownerID, nil
}

func typeFromProto(t pb.SecretType) string {
	switch t {
	case pb.SecretType_SECRET_TYPE_CREDENTIALS:
		return string(domain.SecretTypeCredentials)
	case pb.SecretType_SECRET_TYPE_TEXT:
		return string(domain.SecretTypeText)
	case pb.SecretType_SECRET_TYPE_BINARY:
		return string(domain.SecretTypeBinary)
	case pb.SecretType_SECRET_TYPE_CARD:
		return string(domain.SecretTypeCard)
	default:
		return ""
	}
}

func typeToProto(t string) pb.SecretType {
	switch domain.SecretType(t) {
	case domain.SecretTypeCredentials:
		return pb.SecretType_SECRET_TYPE_CREDENTIALS
	case domain.SecretTypeText:
		return pb.SecretType_SECRET_TYPE_TEXT
	case domain.SecretTypeBinary:
		return pb.SecretType_SECRET_TYPE_BINARY
	case domain.SecretTypeCard:
		return pb.SecretType_SECRET_TYPE_CARD
	default:
		return pb.SecretType_SECRET_TYPE_UNSPECIFIED
	}
}

func mapError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	case errors.Is(err, domain.ErrInvalidSecretID),
		errors.Is(err, domain.ErrUnknownSecretType),
		errors.Is(err, domain.ErrEmptyPayload),
		errors.Is(err, domain.ErrPayloadTooLarge),
		errors.Is(err, domain.ErrMetadataTooLarge):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, domain.ErrSecretNotFound), errors.Is(err, domain.ErrSecretDeleted):
		return status.Error(codes.NotFound, domain.ErrSecretNotFound.Error())
	case errors.Is(err, domain.ErrVersionConflict):
		return status.Error(codes.FailedPrecondition, domain.ErrVersionConflict.Error())
	case errors.Is(err, domain.ErrSecretAlreadyExists):
		return status.Error(codes.AlreadyExists, domain.ErrSecretAlreadyExists.Error())
	case errors.Is(err, vo.ErrInvalidUserID):
		return status.Error(codes.Unauthenticated, "missing authentication")
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
