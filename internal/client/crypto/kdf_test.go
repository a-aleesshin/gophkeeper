package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDeriveDeterministic(t *testing.T) {
	// Arrange
	const login, master = "alice", "correct horse battery"

	// Act
	first := Derive(login, master)
	second := Derive(login, master)

	// Assert
	if first.EncryptionKey != second.EncryptionKey {
		t.Fatal("encryption key is not deterministic")
	}
	if first.AuthPassword != second.AuthPassword {
		t.Fatal("auth password is not deterministic")
	}
}

func TestDeriveDomainSeparation(t *testing.T) {
	// Arrange + Act
	secrets := Derive("alice", "correct horse battery")

	// Assert
	authBytes, err := base64.RawURLEncoding.DecodeString(secrets.AuthPassword)
	if err != nil {
		t.Fatalf("decode auth password: %v", err)
	}
	if bytes.Equal(authBytes, secrets.EncryptionKey[:]) {
		t.Fatal("auth password equals encryption key, domain separation is broken")
	}
}

func TestDeriveDiffersByInput(t *testing.T) {
	// Arrange
	base := Derive("alice", "correct horse battery")

	tests := []struct {
		name   string
		login  string
		master string
	}{
		{name: "different login", login: "bob", master: "correct horse battery"},
		{name: "different password", login: "alice", master: "wrong horse battery"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got := Derive(tt.login, tt.master)

			// Assert
			if got.EncryptionKey == base.EncryptionKey {
				t.Fatal("encryption key collision")
			}
			if got.AuthPassword == base.AuthPassword {
				t.Fatal("auth password collision")
			}
		})
	}
}

func TestDeriveNormalizesLogin(t *testing.T) {
	// Arrange
	const master = "correct horse battery"

	// Act
	base := Derive("alice", master)
	upper := Derive("Alice", master)
	padded := Derive("  ALICE  ", master)

	// Assert
	if base.EncryptionKey != upper.EncryptionKey || base.EncryptionKey != padded.EncryptionKey {
		t.Fatal("encryption key depends on login case or spaces")
	}
	if base.AuthPassword != upper.AuthPassword || base.AuthPassword != padded.AuthPassword {
		t.Fatal("auth password depends on login case or spaces")
	}
}
