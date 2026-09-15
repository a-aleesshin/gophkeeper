package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/a-aleesshin/gophkeeper/internal/client/crypto"
	"github.com/a-aleesshin/gophkeeper/internal/client/storage"
)

type Deps struct {
	Key    crypto.Key
	Store  *storage.Store
	Sync   func(ctx context.Context) (string, error)
	Delete func(ctx context.Context, id string) error
}

func Run(ctx context.Context, deps Deps) error {
	m, err := newModel(ctx, deps)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func loadItems(deps Deps) ([]secretItem, error) {
	vault, err := deps.Store.Load()
	if err != nil {
		return nil, fmt.Errorf("load vault: %w", err)
	}
	records := vault.List()
	items := make([]secretItem, 0, len(records))
	for _, rec := range records {
		meta := ""
		if len(rec.Metadata) > 0 {
			if plain, err := crypto.Open(deps.Key, rec.Metadata, crypto.AADMeta()); err == nil {
				meta = string(plain)
			}
		}
		items = append(items, secretItem{rec: rec, meta: meta})
	}
	return items, nil
}

type secretItem struct {
	rec  storage.Record
	meta string
}

func (i secretItem) Title() string {
	if i.meta != "" {
		return i.meta
	}
	return i.rec.ID
}

func (i secretItem) Description() string {
	return fmt.Sprintf("%s · v%d · %s", i.rec.Type, i.rec.Version, i.rec.UpdatedAt.Local().Format("2006-01-02 15:04"))
}

func (i secretItem) FilterValue() string {
	return i.meta + " " + i.rec.Type
}
