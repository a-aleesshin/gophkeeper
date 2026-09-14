package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	pb "github.com/a-aleesshin/gophkeeper/api/proto/gophkeeper/v1"
	"github.com/a-aleesshin/gophkeeper/internal/client/crypto"
	"github.com/a-aleesshin/gophkeeper/internal/client/session"
	"github.com/a-aleesshin/gophkeeper/internal/client/transport"
)

func registerCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "register <login>",
		Short: "Зарегистрировать нового пользователя",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login := args[0]
			master, err := promptMasterPassword(true)
			if err != nil {
				return err
			}
			derived := crypto.Derive(login, master)

			client, store, err := app.dial()
			if err != nil {
				return err
			}
			defer client.Close()

			ctx := cmd.Context()
			if _, err := client.Identity.Register(ctx, &pb.RegisterRequest{
				Login:    login,
				Password: derived.AuthPassword,
			}); err != nil {
				return err
			}

			if err := doLogin(ctx, client, store, login, derived); err != nil {
				return fmt.Errorf("registered, but login failed: %w", err)
			}
			fmt.Printf("Пользователь %s зарегистрирован, вход выполнен\n", login)
			return nil
		},
	}
}

func loginCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "login <login>",
		Short: "Войти на сервер",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			login := args[0]
			master, err := promptMasterPassword(false)
			if err != nil {
				return err
			}
			derived := crypto.Derive(login, master)

			client, store, err := app.dial()
			if err != nil {
				return err
			}
			defer client.Close()

			if err := doLogin(cmd.Context(), client, store, login, derived); err != nil {
				return err
			}
			fmt.Printf("Вход выполнен: %s\n", login)
			return nil
		},
	}
}

func logoutCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Выйти и удалить локальные данные сессии",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, store, err := app.dial()
			if err != nil {
				return err
			}
			defer client.Close()

			if sess, err := store.Load(); err == nil && sess.RefreshToken != "" {
				if _, err := client.Access.Logout(cmd.Context(), &pb.LogoutRequest{RefreshToken: sess.RefreshToken}); err != nil {
					fmt.Println("Предупреждение: не удалось отозвать сессию на сервере:", err)
				}
			}
			if err := store.Clear(); err != nil {
				return err
			}
			vaultStore, err := app.vaultStore()
			if err != nil {
				return err
			}
			if err := vaultStore.Clear(); err != nil {
				return err
			}
			fmt.Println("Выход выполнен, локальный кэш очищен")
			return nil
		},
	}
}

func doLogin(ctx context.Context, client *transport.Client, store *session.Store, login string, derived crypto.DerivedSecrets) error {
	pair, err := client.Access.Login(ctx, &pb.LoginRequest{
		Login:    login,
		Password: derived.AuthPassword,
	})
	if err != nil {
		return err
	}

	return store.Save(session.Session{
		Login:           login,
		AccessToken:     pair.GetAccessToken(),
		AccessExpiresAt: pair.GetAccessExpiresAt().AsTime(),
		RefreshToken:    pair.GetRefreshToken(),
		EncryptionKey:   derived.EncryptionKey[:],
	})
}
