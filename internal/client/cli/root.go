package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func Execute(version, buildDate string) {
	if err := NewRoot(version, buildDate).ExecuteContext(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func NewRoot(version, buildDate string) *cobra.Command {
	app := &App{}

	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper — клиент менеджера паролей",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&app.server, "server", "localhost:50051", "адрес сервера")

	root.AddCommand(
		registerCmd(app),
		loginCmd(app),
		logoutCmd(app),
		addCmd(app),
		listCmd(app),
		getCmd(app),
		deleteCmd(app),
		syncCmd(app),
		tuiCmd(app),
		versionCmd(version, buildDate),
	)
	return root
}
