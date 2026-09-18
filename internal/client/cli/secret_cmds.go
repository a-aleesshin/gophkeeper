package cli

import (
	"context"
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

func (a *App) sealSecret(secretType string, payload any, meta string) ([]byte, []byte, error) {
	sess, err := a.currentSession()
	if err != nil {
		return nil, nil, err
	}
	key, err := encryptionKey(sess)
	if err != nil {
		return nil, nil, err
	}

	plain, err := crypto.EncodePayload(payload)
	if err != nil {
		return nil, nil, err
	}
	sealedPayload, err := crypto.Seal(key, plain, crypto.AADPayload(secretType))
	if err != nil {
		return nil, nil, err
	}
	if len(sealedPayload) > crypto.MaxSealedPayloadSize {
		return nil, nil, fmt.Errorf("данные слишком велики: %d байт после шифрования при лимите %d (для файлов это примерно 700 КБ)",
			len(sealedPayload), crypto.MaxSealedPayloadSize)
	}

	var sealedMeta []byte
	if meta != "" {
		if sealedMeta, err = crypto.Seal(key, []byte(meta), crypto.AADMeta()); err != nil {
			return nil, nil, err
		}
		if len(sealedMeta) > crypto.MaxSealedMetadataSize {
			return nil, nil, fmt.Errorf("метаинформация слишком велика: %d байт при лимите %d", len(sealedMeta), crypto.MaxSealedMetadataSize)
		}
	}
	return sealedPayload, sealedMeta, nil
}

func (a *App) storeSecret(cmd *cobra.Command, secretType string, payload any, meta string) error {
	sealedPayload, sealedMeta, err := a.sealSecret(secretType, payload, meta)
	if err != nil {
		return err
	}

	id, err := uuid.NewV7()
	if err != nil {
		return err
	}

	if err := a.putRecord(id.String(), secretType, sealedPayload, sealedMeta, false); err != nil {
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

func (a *App) putRecord(id, secretType string, sealedPayload, sealedMeta []byte, mustExist bool) error {
	store, err := a.vaultStore()
	if err != nil {
		return err
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	vault, err := store.Load()
	if err != nil {
		return err
	}
	if mustExist {
		rec, ok := vault.Get(id)
		if !ok || rec.Deleted {
			return fmt.Errorf("секрет %s не найден", id)
		}
		if rec.Type != secretType {
			return fmt.Errorf("секрет %s имеет тип %s, а не %s", id, rec.Type, secretType)
		}
		if sealedMeta == nil {
			sealedMeta = rec.Metadata
		}
	}
	vault.Put(id, secretType, sealedPayload, sealedMeta, time.Now().UTC())
	return store.Save(vault)
}

func (a *App) updateSecret(cmd *cobra.Command, id, secretType string, payload any, meta string, metaSet bool) error {
	sealedPayload, sealedMeta, err := a.sealSecret(secretType, payload, meta)
	if err != nil {
		return err
	}
	if !metaSet {
		sealedMeta = nil
	}
	if err := a.putRecord(id, secretType, sealedPayload, sealedMeta, true); err != nil {
		return err
	}

	client, _, err := a.dial()
	if err == nil {
		defer client.Close()
		trySync(cmd.Context(), client, a)
	}

	fmt.Printf("Секрет %s обновлён\n", id)
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
					if plain, err := crypto.Open(key, rec.Metadata, crypto.AADMeta()); err == nil {
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

			plain, err := crypto.Open(key, rec.Payload, crypto.AADPayload(rec.Type))
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
			if err := app.DeleteSecret(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Printf("Секрет %s удалён\n", args[0])
			return nil
		},
	}
}

func (a *App) DeleteSecret(ctx context.Context, id string) error {
	if err := a.markDeleted(id); err != nil {
		return err
	}

	if client, _, err := a.dial(); err == nil {
		defer client.Close()
		trySync(ctx, client, a)
	}
	return nil
}

func (a *App) markDeleted(id string) error {
	store, err := a.vaultStore()
	if err != nil {
		return err
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	defer unlock()

	vault, err := store.Load()
	if err != nil {
		return err
	}
	if !vault.MarkDeleted(id, time.Now().UTC()) {
		return fmt.Errorf("секрет %s не найден", id)
	}
	return store.Save(vault)
}

func editCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Изменить существующий секрет",
	}
	cmd.AddCommand(editCredentialsCmd(app), editTextCmd(app), editCardCmd(app), editBinaryCmd(app))
	return cmd
}

func editCredentialsCmd(app *App) *cobra.Command {
	var login, meta string
	cmd := &cobra.Command{
		Use:   "credentials <id>",
		Short: "Обновить пару логин/пароль",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := promptPassword("Пароль секрета: ")
			if err != nil {
				return err
			}
			return app.updateSecret(cmd, args[0], "credentials",
				crypto.Credentials{Login: login, Password: password}, meta, cmd.Flags().Changed("meta"))
		},
	}
	cmd.Flags().StringVar(&login, "login", "", "логин")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}

func editTextCmd(app *App) *cobra.Command {
	var content, meta string
	cmd := &cobra.Command{
		Use:   "text <id>",
		Short: "Обновить текст",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.updateSecret(cmd, args[0], "text",
				crypto.Text{Content: content}, meta, cmd.Flags().Changed("meta"))
		},
	}
	cmd.Flags().StringVar(&content, "content", "", "текст")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("content")
	return cmd
}

func editCardCmd(app *App) *cobra.Command {
	var number, holder, meta string
	var expMonth, expYear int
	cmd := &cobra.Command{
		Use:   "card <id>",
		Short: "Обновить карту",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cvc, err := promptPassword("CVC: ")
			if err != nil {
				return err
			}
			payload := crypto.Card{Number: number, Holder: holder, ExpMonth: expMonth, ExpYear: expYear, CVC: cvc}
			return app.updateSecret(cmd, args[0], "card", payload, meta, cmd.Flags().Changed("meta"))
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

func editBinaryCmd(app *App) *cobra.Command {
	var file, meta string
	cmd := &cobra.Command{
		Use:   "binary <id>",
		Short: "Обновить бинарные данные из файла",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			payload := crypto.Binary{Name: filepath.Base(file), Data: data}
			return app.updateSecret(cmd, args[0], "binary", payload, meta, cmd.Flags().Changed("meta"))
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "путь к файлу")
	cmd.Flags().StringVar(&meta, "meta", "", "метаинформация")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}
