package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func versionCmd(version, buildDate string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Версия и дата сборки",
		Args:  cobra.NoArgs,
		Run: func(*cobra.Command, []string) {
			fmt.Printf("gophkeeper client\nversion:    %s\nbuild date: %s\n", version, buildDate)
		},
	}
}
