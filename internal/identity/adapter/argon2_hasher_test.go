package adapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
)

func mustPassword(t *testing.T, s string) domain.Password {
	t.Helper()
	p, err := domain.NewPassword(s)
	if err != nil {
		t.Fatalf("NewPassword: %v", err)
	}
	return p
}

func TestArgon2HasherRoundtrip(t *testing.T) {
	// Arrange
	h := NewArgon2Hasher()
	password := mustPassword(t, "correct horse battery")

	// Act
	hash, err := h.Hash(context.Background(), password)

	// Assert
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(string(hash.Bytes()), "$argon2id$") {
		t.Fatalf("hash format = %q, want $argon2id$ prefix", hash.Bytes())
	}
	if strings.Contains(string(hash.Bytes()), "correct horse battery") {
		t.Fatal("hash contains plaintext password")
	}

	ok, err := h.Compare(context.Background(), hash, password)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !ok {
		t.Fatal("Compare = false for correct password")
	}
}

func TestArgon2HasherWrongPassword(t *testing.T) {
	// Arrange
	h := NewArgon2Hasher()
	hash, err := h.Hash(context.Background(), mustPassword(t, "correct horse battery"))
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// Act
	ok, err := h.Compare(context.Background(), hash, mustPassword(t, "wrong horse battery"))

	// Assert
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if ok {
		t.Fatal("Compare = true for wrong password")
	}
}

func TestArgon2HasherSaltUniqueness(t *testing.T) {
	// Arrange
	h := NewArgon2Hasher()
	password := mustPassword(t, "correct horse battery")

	// Act
	first, err := h.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	second, err := h.Hash(context.Background(), password)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// Assert
	if string(first.Bytes()) == string(second.Bytes()) {
		t.Fatal("two hashes of same password are identical, salt is not random")
	}
}

func TestArgon2HasherMalformedHash(t *testing.T) {
	// Arrange
	h := NewArgon2Hasher()
	tests := []struct {
		name string
		hash string
	}{
		{name: "garbage", hash: "not-a-hash"},
		{name: "wrong algorithm", hash: "$bcrypt$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{name: "wrong version", hash: "$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{name: "broken params", hash: "$argon2id$v=19$m=abc$c2FsdA$aGFzaA"},
		{name: "broken salt base64", hash: "$argon2id$v=19$m=65536,t=3,p=4$%%%$aGFzaA"},
		{name: "broken key base64", hash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$%%%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			malformed, err := domain.NewPasswordHash([]byte(tt.hash))
			if err != nil {
				t.Fatalf("NewPasswordHash: %v", err)
			}

			// Act
			_, err = h.Compare(context.Background(), malformed, mustPassword(t, "correct horse battery"))

			// Assert
			if !errors.Is(err, ErrMalformedHash) {
				t.Fatalf("Compare error = %v, want ErrMalformedHash", err)
			}
		})
	}
}
