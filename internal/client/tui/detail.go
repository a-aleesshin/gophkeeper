package tui

import (
	"fmt"
	"strings"

	"github.com/a-aleesshin/gophkeeper/internal/client/crypto"
	"github.com/a-aleesshin/gophkeeper/internal/client/storage"
)

func formatDetail(key crypto.Key, rec storage.Record, meta string) string {
	plain, err := crypto.Open(key, rec.Payload, crypto.AADPayload(rec.Type))
	if err != nil {
		return "Расшифровка не удалась: " + err.Error()
	}

	var b strings.Builder
	if meta != "" {
		fmt.Fprintf(&b, "Метка:     %s\n", meta)
	}
	fmt.Fprintf(&b, "ID:        %s\nТип:       %s\nВерсия:    %d\nОбновлён:  %s\n\n",
		rec.ID, rec.Type, rec.Version, rec.UpdatedAt.Local().Format("2006-01-02 15:04:05"))

	switch rec.Type {
	case "credentials":
		v, err := crypto.DecodePayload[crypto.Credentials](plain)
		if err != nil {
			return b.String() + "Ошибка декодирования: " + err.Error()
		}
		fmt.Fprintf(&b, "Логин:     %s\nПароль:    %s\n", v.Login, v.Password)
	case "text":
		v, err := crypto.DecodePayload[crypto.Text](plain)
		if err != nil {
			return b.String() + "Ошибка декодирования: " + err.Error()
		}
		fmt.Fprintf(&b, "%s\n", v.Content)
	case "card":
		v, err := crypto.DecodePayload[crypto.Card](plain)
		if err != nil {
			return b.String() + "Ошибка декодирования: " + err.Error()
		}
		fmt.Fprintf(&b, "Номер:     %s\nДержатель: %s\nСрок:      %02d/%d\nCVC:       %s\n",
			v.Number, v.Holder, v.ExpMonth, v.ExpYear, v.CVC)
	case "binary":
		v, err := crypto.DecodePayload[crypto.Binary](plain)
		if err != nil {
			return b.String() + "Ошибка декодирования: " + err.Error()
		}
		fmt.Fprintf(&b, "Файл:      %s (%d байт)\nСохранить: gophkeeper get %s --out <файл>\n", v.Name, len(v.Data), rec.ID)
	}
	return b.String()
}
