package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/a-aleesshin/gophkeeper/internal/client/tui"
)

func tuiCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Интерактивный терминальный интерфейс",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sess, err := app.currentSession()
			if err != nil {
				return err
			}
			key, err := encryptionKey(sess)
			if err != nil {
				return err
			}
			store, err := app.vaultStore()
			if err != nil {
				return err
			}

			if client, _, err := app.dial(); err == nil {
				trySync(cmd.Context(), client, app)
				client.Close()
			}

			deps := tui.Deps{
				Key:   key,
				Store: store,
				Sync: func(ctx context.Context) (string, error) {
					client, _, err := app.dial()
					if err != nil {
						return "", err
					}
					defer client.Close()
					summary, err := runSync(ctx, client, app)
					if err != nil {
						return "", err
					}
					return fmt.Sprintf("отправлено %d, получено %d, конфликтов %d",
						summary.Pushed, summary.Pulled, len(summary.Conflicts)), nil
				},
				Delete: app.DeleteSecret,
			}
			return tui.Run(cmd.Context(), deps)
		},
	}
}
