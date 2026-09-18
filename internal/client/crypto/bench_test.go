package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkDerive(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Derive("alice", "correct horse battery")
	}
}

func benchmarkSeal(b *testing.B, size int) {
	key := testKey(1)
	plaintext := make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("rand: %v", err)
	}
	aad := AADPayload("binary")

	b.ReportAllocs()
	b.SetBytes(int64(size))
	for b.Loop() {
		if _, err := Seal(key, plaintext, aad); err != nil {
			b.Fatalf("Seal: %v", err)
		}
	}
}

func benchmarkOpen(b *testing.B, size int) {
	key := testKey(1)
	plaintext := make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("rand: %v", err)
	}
	aad := AADPayload("binary")
	envelope, err := Seal(key, plaintext, aad)
	if err != nil {
		b.Fatalf("Seal: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(size))
	for b.Loop() {
		if _, err := Open(key, envelope, aad); err != nil {
			b.Fatalf("Open: %v", err)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) { benchmarkSeal(b, size) })
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) { benchmarkOpen(b, size) })
	}
}

func BenchmarkPayloadEncode(b *testing.B) {
	creds := Credentials{Login: "alice@bank.com", Password: "correct horse battery"}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodePayload(creds); err != nil {
			b.Fatalf("EncodePayload: %v", err)
		}
	}
}

func BenchmarkPayloadDecode(b *testing.B) {
	data, err := EncodePayload(Credentials{Login: "alice@bank.com", Password: "correct horse battery"})
	if err != nil {
		b.Fatalf("EncodePayload: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodePayload[Credentials](data); err != nil {
			b.Fatalf("DecodePayload: %v", err)
		}
	}
}
