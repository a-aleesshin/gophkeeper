package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
	"github.com/a-aleesshin/gophkeeper/internal/vault/domain"
)

type ChangedSecretsLister interface {
	ListChangedSince(ctx context.Context, ownerID vo.UserID, since time.Time) ([]domain.Secret, error)
}

type TxRunner interface {
	InTx(ctx context.Context, fn func(ctx context.Context) error) error
}

type SyncItem struct {
	SecretID    string
	Type        string
	Payload     []byte
	Metadata    []byte
	Deleted     bool
	BaseVersion int64
}

type SyncAppliedItem struct {
	SecretID string
	Version  int64
}

type SyncConflict struct {
	SecretID       string
	ServerType     string
	ServerPayload  []byte
	ServerMetadata []byte
	ServerDeleted  bool
	ServerVersion  int64
	UpdatedAt      time.Time
}

type SyncChange struct {
	SecretID  string
	Type      string
	Payload   []byte
	Metadata  []byte
	Deleted   bool
	Version   int64
	UpdatedAt time.Time
}

type SyncSecretsCommand struct {
	OwnerID vo.UserID
	Since   time.Time
	Items   []SyncItem
}

type SyncSecretsResult struct {
	Applied   []SyncAppliedItem
	Conflicts []SyncConflict
	Changes   []SyncChange
	Cursor    time.Time
}

type SyncSecretsHandler struct {
	provider SecretProvider
	creator  SecretCreator
	saver    SecretSaver
	changes  ChangedSecretsLister
	tx       TxRunner
	clock    clock.Clock
}

func NewSyncSecretsHandler(
	provider SecretProvider,
	creator SecretCreator,
	saver SecretSaver,
	changes ChangedSecretsLister,
	tx TxRunner,
	clk clock.Clock,
) SyncSecretsHandler {
	return SyncSecretsHandler{provider: provider, creator: creator, saver: saver, changes: changes, tx: tx, clock: clk}
}

func (h SyncSecretsHandler) Handle(ctx context.Context, cmd SyncSecretsCommand) (SyncSecretsResult, error) {
	if cmd.OwnerID.IsZero() {
		return SyncSecretsResult{}, vo.ErrInvalidUserID
	}

	result := SyncSecretsResult{}
	err := h.tx.InTx(ctx, func(ctx context.Context) error {
		now := h.clock.Now()
		result = SyncSecretsResult{Cursor: now}
		touched := make(map[string]struct{}, len(cmd.Items))

		for _, item := range cmd.Items {
			applied, conflict, err := h.applyItem(ctx, cmd.OwnerID, item, now)
			if err != nil {
				return fmt.Errorf("apply item %s: %w", item.SecretID, err)
			}

			touched[item.SecretID] = struct{}{}
			if conflict != nil {
				result.Conflicts = append(result.Conflicts, *conflict)
				continue
			}

			result.Applied = append(result.Applied, *applied)
		}

		serverChanges, err := h.changes.ListChangedSince(ctx, cmd.OwnerID, cmd.Since)
		if err != nil {
			return fmt.Errorf("list changes: %w", err)
		}

		for _, serverChange := range serverChanges {
			if _, ok := touched[serverChange.ID().String()]; ok {
				continue
			}

			result.Changes = append(result.Changes, SyncChange{
				SecretID:  serverChange.ID().String(),
				Type:      serverChange.Type().String(),
				Payload:   serverChange.Payload().Bytes(),
				Metadata:  serverChange.Metadata().Bytes(),
				Deleted:   serverChange.IsDeleted(),
				Version:   serverChange.Version(),
				UpdatedAt: serverChange.UpdatedAt(),
			})
		}

		return nil
	})

	if err != nil {
		return SyncSecretsResult{}, err
	}
	return result, nil
}

func (h SyncSecretsHandler) applyItem(ctx context.Context, ownerID vo.UserID, item SyncItem, now time.Time) (*SyncAppliedItem, *SyncConflict, error) {
	id, err := domain.ParseSecretID(item.SecretID)
	if err != nil {
		return nil, nil, err
	}

	existing, err := h.provider.Get(ctx, ownerID, id)
	switch {
	case errors.Is(err, domain.ErrSecretNotFound):
		return h.applyMissing(ctx, ownerID, id, item, now)
	case err != nil:
		return nil, nil, fmt.Errorf("get: %w", err)
	}

	return h.applyExisting(ctx, existing, item, now)
}

func (h SyncSecretsHandler) applyMissing(ctx context.Context, ownerID vo.UserID, id domain.SecretID, item SyncItem, now time.Time) (*SyncAppliedItem, *SyncConflict, error) {
	if item.Deleted {
		return &SyncAppliedItem{SecretID: item.SecretID, Version: 0}, nil, nil
	}

	secretType, err := domain.ParseSecretType(item.Type)
	if err != nil {
		return nil, nil, err
	}

	payload, err := domain.NewPayload(item.Payload)
	if err != nil {
		return nil, nil, err
	}

	metadata, err := domain.NewMetadata(item.Metadata)
	if err != nil {
		return nil, nil, err
	}

	secret, err := domain.NewSecret(id, ownerID, secretType, payload, metadata, now)
	if err != nil {
		return nil, nil, err
	}
	if err := h.creator.Create(ctx, secret); err != nil {
		return nil, nil, fmt.Errorf("create: %w", err)
	}

	return &SyncAppliedItem{SecretID: item.SecretID, Version: secret.Version()}, nil, nil
}

func (h SyncSecretsHandler) applyExisting(ctx context.Context, existing domain.Secret, item SyncItem, now time.Time) (*SyncAppliedItem, *SyncConflict, error) {
	if item.Deleted {
		if existing.IsDeleted() {
			return &SyncAppliedItem{SecretID: item.SecretID, Version: existing.Version()}, nil, nil
		}

		deleted, err := existing.Delete(item.BaseVersion, now)
		if err != nil {
			return nil, conflictOf(existing), nil
		}
		if err := h.saver.Save(ctx, deleted); err != nil {
			return nil, nil, fmt.Errorf("save tombstone: %w", err)
		}

		return &SyncAppliedItem{SecretID: item.SecretID, Version: deleted.Version()}, nil, nil
	}

	payload, err := domain.NewPayload(item.Payload)
	if err != nil {
		return nil, nil, err
	}

	metadata, err := domain.NewMetadata(item.Metadata)
	if err != nil {
		return nil, nil, err
	}

	updated, err := existing.Update(payload, metadata, item.BaseVersion, now)
	if err != nil {
		return nil, conflictOf(existing), nil
	}
	if err := h.saver.Save(ctx, updated); err != nil {
		return nil, nil, fmt.Errorf("save: %w", err)
	}

	return &SyncAppliedItem{SecretID: item.SecretID, Version: updated.Version()}, nil, nil
}

func conflictOf(s domain.Secret) *SyncConflict {
	return &SyncConflict{
		SecretID:       s.ID().String(),
		ServerType:     s.Type().String(),
		ServerPayload:  s.Payload().Bytes(),
		ServerMetadata: s.Metadata().Bytes(),
		ServerDeleted:  s.IsDeleted(),
		ServerVersion:  s.Version(),
		UpdatedAt:      s.UpdatedAt(),
	}
}
