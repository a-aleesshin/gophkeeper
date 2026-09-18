package adapter

import (
	"context"
	"testing"

	"github.com/a-aleesshin/gophkeeper/internal/identity/domain"
)

func BenchmarkArgon2Hash(b *testing.B) {
	h := NewArgon2Hasher()
	password, err := domain.NewPassword("correct horse battery")
	if err != nil {
		b.Fatalf("NewPassword: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := h.Hash(context.Background(), password); err != nil {
			b.Fatalf("Hash: %v", err)
		}
	}
}

func BenchmarkArgon2Compare(b *testing.B) {
	h := NewArgon2Hasher()
	password, err := domain.NewPassword("correct horse battery")
	if err != nil {
		b.Fatalf("NewPassword: %v", err)
	}
	hash, err := h.Hash(context.Background(), password)
	if err != nil {
		b.Fatalf("Hash: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		ok, err := h.Compare(context.Background(), hash, password)
		if err != nil || !ok {
			b.Fatalf("Compare: ok=%v err=%v", ok, err)
		}
	}
}
