package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

type Store struct {
	path string
}

func NewStore(path string) *Store {
	return &Store{path: path}
}

func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve config dir: %w", err)
	}
	return filepath.Join(dir, "gophkeeper", "vault.json"), nil
}

func (s *Store) Load() (*Vault, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewVault(), nil
		}
		return nil, fmt.Errorf("read vault: %w", err)
	}

	vault := NewVault()
	if err := json.Unmarshal(data, vault); err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}
	if vault.Records == nil {
		vault.Records = make(map[string]Record)
	}
	return vault, nil
}

func (s *Store) Save(vault *Vault) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create vault dir: %w", err)
	}
	data, err := json.Marshal(vault)
	if err != nil {
		return fmt.Errorf("encode vault: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), "vault-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp vault: %w", err)
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp vault: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp vault: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp vault: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("replace vault: %w", err)
	}
	return nil
}

func (s *Store) Clear() error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove vault: %w", err)
	}
	return nil
}

func (s *Store) Lock() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, fmt.Errorf("create vault dir: %w", err)
	}
	fl := flock.New(s.path + ".lock")
	if err := fl.Lock(); err != nil {
		return nil, fmt.Errorf("lock vault: %w", err)
	}
	return func() { _ = fl.Unlock() }, nil
}
