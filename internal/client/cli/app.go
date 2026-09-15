package cli

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"

	"github.com/a-aleesshin/gophkeeper/internal/client/crypto"
	"github.com/a-aleesshin/gophkeeper/internal/client/session"
	"github.com/a-aleesshin/gophkeeper/internal/client/storage"
	"github.com/a-aleesshin/gophkeeper/internal/client/transport"
	"github.com/a-aleesshin/gophkeeper/internal/platform/clock"
)

type App struct {
	server string
}

func (a *App) sessionStore() (*session.Store, error) {
	path, err := session.DefaultPath()
	if err != nil {
		return nil, err
	}
	return session.NewStore(path), nil
}

func (a *App) vaultStore() (*storage.Store, error) {
	path, err := storage.DefaultPath()
	if err != nil {
		return nil, err
	}
	return storage.NewStore(path), nil
}

func (a *App) dial() (*transport.Client, *session.Store, error) {
	store, err := a.sessionStore()
	if err != nil {
		return nil, nil, err
	}
	client, err := transport.New(a.server, store, clock.System{})
	if err != nil {
		return nil, nil, err
	}
	return client, store, nil
}

func (a *App) currentSession() (session.Session, error) {
	store, err := a.sessionStore()
	if err != nil {
		return session.Session{}, err
	}
	sess, err := store.Load()
	if err != nil {
		return session.Session{}, transport.ErrNotAuthenticated
	}
	return sess, nil
}

func encryptionKey(sess session.Session) (crypto.Key, error) {
	var key crypto.Key
	if len(sess.EncryptionKey) != len(key) {
		return key, fmt.Errorf("session has no valid encryption key, run login again")
	}
	copy(key[:], sess.EncryptionKey)
	return key, nil
}

func promptPassword(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	raw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return string(raw), nil
}

func promptMasterPassword(confirm bool) (string, error) {
	password, err := promptPassword("Мастер-пароль: ")
	if err != nil {
		return "", err
	}
	if !confirm {
		return password, nil
	}
	repeat, err := promptPassword("Повторите мастер-пароль: ")
	if err != nil {
		return "", err
	}
	if password != repeat {
		return "", fmt.Errorf("пароли не совпадают")
	}
	return password, nil
}


