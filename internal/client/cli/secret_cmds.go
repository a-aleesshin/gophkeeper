package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/a-aleesshin/gophkeeper/internal/client/crypto"
	"github.com/a-aleesshin/gophkeeper/internal/client/storage"
)

func addCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Добавить секрет",
	}
	cmd.AddCommand(addCredentialsCmd(app), addTextCmd(app), addBinaryCmd(app), addCardCmd(app))
	return cmd
}

func addCredentialsCmd(app *App) *cobra.Command {
	var login, meta string
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Пара логин/пароль",
		RunE: func(cmd *cobra.Command, _ []string) error {
			password, err := promptPassword("Пароль секрета: ")
			if err != nil {
				return err
			}
			return app.storeSecret(cmd, "credentials", crypto.Credentials{Login: login, Password: password}, meta)
		},
	}
	cmd.Flags().StringVar(&login, "login", "", "логин")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func addTextCmd(app *App) *cobra.Command {
	var content, meta string
	cmd := &cobra.Command{
		Use:   "text",
		Short: "Произвольный текст",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return app.storeSecret(cmd, "text", crypto.Text{Content: content}, meta)
		},
	}
	cmd.Flags().StringVar(&content, "content", "", "текст")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("content")
	return cmd
}

func addBinaryCmd(app *App) *cobra.Command {
	var file, meta string
	cmd := &cobra.Command{
		Use:   "binary",
		Short: "Бинарные данные из файла",
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			payload := crypto.Binary{Name: filepath.Base(file), Data: data}
			return app.storeSecret(cmd, "binary", payload, meta)
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "путь к файлу")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func addCardCmd(app *App) *cobra.Command {
	var number, holder, meta string
	var expMonth, expYear int
	cmd := &cobra.Command{
		Use:   "card",
		Short: "Банковская карта",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cvc, err := promptPassword("CVC: ")
			if err != nil {
				return err
			}
			payload := crypto.Card{Number: number, Holder: holder, ExpMonth: expMonth, ExpYear: expYear, CVC: cvc}
			return app.storeSecret(cmd, "card", payload, meta)
		},
	}
	cmd.Flags().StringVar(&number, "number", "", "номер карты")
	cmd.Flags().StringVar(&holder, "holder", "", "держатель")
	cmd.Flags().IntVar(&expMonth, "exp-month", 0, "месяц окончания")
	cmd.Flags().IntVar(&expYear, "exp-year", 0, "год окончания")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("number")
	return cmd
}

func (a *App) storeSecret(cmd *cobra.Command, secretType string, payload any, meta string) error {
	sess, err := a.currentSession()
	if err != nil {
		return err
	}
	key, err := encryptionKey(sess)
	if err != nil {
		return err
	}

	plain, err := crypto.EncodePayload(payload)
	if err != nil {
		return err
	}
	sealedPayload, err := crypto.Seal(key, plain, aadPayload(secretType))
	if err != nil {
		return err
	}
	var sealedMeta []byte
	if meta != "" {
		if sealedMeta, err = crypto.Seal(key, []byte(meta), aadMeta()); err != nil {
			return err
		}
	}

	id, err := uuid.NewV7()
	if err != nil {
		return err
	}

	store, err := a.vaultStore()
	if err != nil {
		return err
	}
	vault, err := store.Load()
	if err != nil {
		return err
	}
	vault.Put(id.String(), secretType, sealedPayload, sealedMeta, time.Now().UTC())
	if err := store.Save(vault); err != nil {
		return err
	}

	client, _, err := a.dial()
	if err == nil {
		defer client.Close()
		trySync(cmd.Context(), client, a)
	}

	fmt.Printf("Секрет сохранён: %s\n", id)
	return nil
}

func listCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Список секретов",
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

			if client, _, err := app.dial(); err == nil {
				defer client.Close()
				trySync(cmd.Context(), client, app)
			}

			store, err := app.vaultStore()
			if err != nil {
				return err
			}
			vault, err := store.Load()
			if err != nil {
				return err
			}

			records := vault.List()
			if len(records) == 0 {
				fmt.Println("Секретов нет")
				return nil
			}
			for _, rec := range records {
				meta := ""
				if len(rec.Metadata) > 0 {
					if plain, err := crypto.Open(key, rec.Metadata, aadMeta()); err == nil {
						meta = string(plain)
					} else {
						meta = "<не расшифровано>"
					}
				}
				fmt.Printf("%s  %-11s  v%-3d  %s  %s\n",
					rec.ID, rec.Type, rec.Version, rec.UpdatedAt.Local().Format("2006-01-02 15:04"), meta)
			}
			return nil
		},
	}
}

func getCmd(app *App) *cobra.Command {
	var outFile string
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Показать секрет",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := app.currentSession()
			if err != nil {
				return err
			}
			key, err := encryptionKey(sess)
			if err != nil {
				return err
			}

			if client, _, err := app.dial(); err == nil {
				defer client.Close()
				trySync(cmd.Context(), client, app)
			}

			store, err := app.vaultStore()
			if err != nil {
				return err
			}
			vault, err := store.Load()
			if err != nil {
				return err
			}
			rec, ok := vault.Get(args[0])
			if !ok || rec.Deleted {
				return fmt.Errorf("секрет %s не найден", args[0])
			}

			plain, err := crypto.Open(key, rec.Payload, aadPayload(rec.Type))
			if err != nil {
				return fmt.Errorf("расшифровка не удалась: %w", err)
			}
			return printSecret(rec, plain, outFile)
		},
	}
	cmd.Flags().StringVar(&outFile, "out", "", "файл для сохранения бинарных данных")
	return cmd
}

func printSecret(rec storage.Record, plain []byte, outFile string) error {
	switch rec.Type {
	case "credentials":
		v, err := crypto.DecodePayload[crypto.Credentials](plain)
		if err != nil {
			return err
		}
		fmt.Printf("Логин:  %s\nПароль: %s\n", v.Login, v.Password)
	case "text":
		v, err := crypto.DecodePayload[crypto.Text](plain)
		if err != nil {
			return err
		}
		fmt.Println(v.Content)
	case "card":
		v, err := crypto.DecodePayload[crypto.Card](plain)
		if err != nil {
			return err
		}
		fmt.Printf("Номер:     %s\nДержатель: %s\nСрок:      %02d/%d\nCVC:       %s\n", v.Number, v.Holder, v.ExpMonth, v.ExpYear, v.CVC)
	case "binary":
		v, err := crypto.DecodePayload[crypto.Binary](plain)
		if err != nil {
			return err
		}
		if outFile == "" {
			outFile = v.Name
		}
		if err := os.WriteFile(outFile, v.Data, 0o600); err != nil {
			return fmt.Errorf("write file: %w", err)
		}
		fmt.Printf("Файл %s (%d байт) сохранён в %s\n", v.Name, len(v.Data), outFile)
	default:
		return fmt.Errorf("неизвестный тип секрета: %s", rec.Type)
	}
	return nil
}

func deleteCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <id>",
		Short: "Удалить секрет",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := app.vaultStore()
			if err != nil {
				return err
			}
			vault, err := store.Load()
			if err != nil {
				return err
			}
			if !vault.MarkDeleted(args[0], time.Now().UTC()) {
				return fmt.Errorf("секрет %s не найден", args[0])
			}
			if err := store.Save(vault); err != nil {
				return err
			}

			if client, _, err := app.dial(); err == nil {
				defer client.Close()
				trySync(cmd.Context(), client, app)
			}
			fmt.Printf("Секрет %s удалён\n", args[0])
			return nil
		},
	}
}
