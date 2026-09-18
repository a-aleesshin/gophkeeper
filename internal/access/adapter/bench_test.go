package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
	vo "github.com/a-aleesshin/gophkeeper/internal/kernel/valueobject"
)

type benchClock struct{}

func (benchClock) Now() time.Time { return time.Now().UTC() }

func benchUserID(b *testing.B) vo.UserID {
	b.Helper()
	id, err := vo.UserIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		b.Fatalf("UserIDFromUUID: %v", err)
	}
	return id
}

func BenchmarkJWTIssue(b *testing.B) {
	m, err := NewJWTManager(testSecret, 15*time.Minute, benchClock{})
	if err != nil {
		b.Fatalf("NewJWTManager: %v", err)
	}
	userID := benchUserID(b)

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := m.Issue(context.Background(), userID, time.Now().UTC()); err != nil {
			b.Fatalf("Issue: %v", err)
		}
	}
}

func BenchmarkJWTVerify(b *testing.B) {
	m, err := NewJWTManager(testSecret, 15*time.Minute, benchClock{})
	if err != nil {
		b.Fatalf("NewJWTManager: %v", err)
	}
	token, _, err := m.Issue(context.Background(), benchUserID(b), time.Now().UTC())
	if err != nil {
		b.Fatalf("Issue: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := m.Verify(context.Background(), token); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

func BenchmarkRefreshTokenCodecNew(b *testing.B) {
	codec := NewRefreshTokenCodec()
	id, err := domain.TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		b.Fatalf("TokenIDFromUUID: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := codec.New(id); err != nil {
			b.Fatalf("New: %v", err)
		}
	}
}

func BenchmarkRefreshTokenCodecParse(b *testing.B) {
	codec := NewRefreshTokenCodec()
	id, err := domain.TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		b.Fatalf("TokenIDFromUUID: %v", err)
	}
	plaintext, _, err := codec.New(id)
	if err != nil {
		b.Fatalf("New: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := codec.Parse(plaintext); err != nil {
			b.Fatalf("Parse: %v", err)
		}
	}
}
