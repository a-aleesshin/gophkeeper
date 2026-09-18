package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/client/storage"
	"github.com/a-aleesshin/gophkeeper/internal/client/transport"
)

var typeToProto = map[string]pb.SecretType{
	"credentials": pb.SecretType_SECRET_TYPE_CREDENTIALS,
	"text":        pb.SecretType_SECRET_TYPE_TEXT,
	"binary":      pb.SecretType_SECRET_TYPE_BINARY,
	"card":        pb.SecretType_SECRET_TYPE_CARD,
}

var typeFromProto = map[pb.SecretType]string{
	pb.SecretType_SECRET_TYPE_CREDENTIALS: "credentials",
	pb.SecretType_SECRET_TYPE_TEXT:        "text",
	pb.SecretType_SECRET_TYPE_BINARY:      "binary",
	pb.SecretType_SECRET_TYPE_CARD:        "card",
}

type syncSummary struct {
	Pushed    int
	Pulled    int
	Conflicts []string
}

func syncCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Синхронизировать данные с сервером",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, err := app.dial()
			if err != nil {
				return err
			}
			defer client.Close()

			summary, err := runSync(cmd.Context(), client, app)
			if err != nil {
				return err
			}
			fmt.Printf("Синхронизация завершена: отправлено %d, получено %d\n", summary.Pushed, summary.Pulled)
			for _, id := range summary.Conflicts {
				fmt.Printf("Конфликт по записи %s: применена версия сервера\n", id)
			}
			return nil
		},
	}
}

func runSync(ctx context.Context, client *transport.Client, app *App) (syncSummary, error) {
	store, err := app.vaultStore()
	if err != nil {
		return syncSummary{}, err
	}
	unlock, err := store.Lock()
	if err != nil {
		return syncSummary{}, err
	}
	defer unlock()

	vault, err := store.Load()
	if err != nil {
		return syncSummary{}, err
	}

	dirty := vault.DirtyRecords()
	items := make([]*pb.SyncItem, 0, len(dirty))
	for _, rec := range dirty {
		items = append(items, &pb.SyncItem{
			SecretId:    rec.ID,
			Type:        typeToProto[rec.Type],
			Payload:     rec.Payload,
			Metadata:    rec.Metadata,
			Deleted:     rec.Deleted,
			BaseVersion: rec.Version,
		})
	}

	req := &pb.SyncSecretsRequest{Items: items}
	if !vault.Cursor.IsZero() {
		req.Since = timestamppb.New(vault.Cursor)
	}

	resp, err := client.Vault.SyncSecrets(ctx, req)
	if err != nil {
		return syncSummary{}, err
	}

	summary := syncSummary{Pushed: len(resp.GetApplied()), Pulled: len(resp.GetChanges())}

	for _, applied := range resp.GetApplied() {
		vault.MarkSynced(applied.GetSecretId(), applied.GetVersion())
	}
	for _, conflict := range resp.GetConflicts() {
		summary.Conflicts = append(summary.Conflicts, conflict.GetSecretId())
		vault.ApplyServer(storage.Record{
			ID:        conflict.GetSecretId(),
			Type:      typeFromProto[conflict.GetServerType()],
			Payload:   conflict.GetServerPayload(),
			Metadata:  conflict.GetServerMetadata(),
			Version:   conflict.GetServerVersion(),
			Deleted:   conflict.GetServerDeleted(),
			UpdatedAt: conflict.GetUpdatedAt().AsTime(),
		})
	}
	for _, change := range resp.GetChanges() {
		vault.ApplyServer(storage.Record{
			ID:        change.GetSecretId(),
			Type:      typeFromProto[change.GetType()],
			Payload:   change.GetPayload(),
			Metadata:  change.GetMetadata(),
			Version:   change.GetVersion(),
			Deleted:   change.GetDeleted(),
			UpdatedAt: change.GetUpdatedAt().AsTime(),
		})
	}

	vault.Cursor = resp.GetCursor().AsTime()
	if err := store.Save(vault); err != nil {
		return syncSummary{}, err
	}
	return summary, nil
}

func trySync(ctx context.Context, client *transport.Client, app *App) {
	if _, err := runSync(ctx, client, app); err != nil {
		fmt.Println("Предупреждение: синхронизация не удалась, работаем локально:", err)
	}
}
