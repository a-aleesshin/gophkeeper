package adapter

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/a-aleesshin/gophkeeper/internal/access/domain"
)

func mustTokenID(t *testing.T) domain.TokenID {
	t.Helper()
	id, err := domain.TokenIDFromUUID(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("TokenIDFromUUID: %v", err)
	}
	return id
}

func TestRefreshTokenCodecRoundtrip(t *testing.T) {
	// Arrange
	codec := NewRefreshTokenCodec()
	id := mustTokenID(t)

	// Act
	plaintext, hash, err := codec.New(id)

	// Assert
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(plaintext, id.String()+".") {
		t.Fatalf("plaintext = %q, want prefix %q", plaintext, id.String()+".")
	}
	parsedID, parsedHash, err := codec.Parse(plaintext)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsedID != id {
		t.Fatalf("parsed id = %v, want %v", parsedID, id)
	}
	if !parsedHash.Equal(hash) {
		t.Fatal("parsed hash does not match issued hash")
	}
}

func TestRefreshTokenCodecUniqueSecrets(t *testing.T) {
	// Arrange
	codec := NewRefreshTokenCodec()
	id := mustTokenID(t)

	// Act
	first, firstHash, err := codec.New(id)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	second, secondHash, err := codec.New(id)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Assert
	if first == second {
		t.Fatal("two generated tokens are identical")
	}
	if firstHash.Equal(secondHash) {
		t.Fatal("two generated hashes are identical")
	}
}

func TestRefreshTokenCodecNewZeroID(t *testing.T) {
	// Act
	_, _, err := NewRefreshTokenCodec().New(domain.TokenID{})

	// Assert
	if !errors.Is(err, domain.ErrInvalidTokenID) {
		t.Fatalf("New error = %v, want ErrInvalidTokenID", err)
	}
}

func TestRefreshTokenCodecParseErrors(t *testing.T) {
	// Arrange
	codec := NewRefreshTokenCodec()
	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "no separator", token: "abcdef"},
		{name: "bad uuid", token: "not-a-uuid.secret"},
		{name: "nil uuid", token: "00000000-0000-0000-0000-000000000000.secret"},
		{name: "empty secret", token: uuid.Must(uuid.NewV7()).String() + "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			_, _, err := codec.Parse(tt.token)

			// Assert
			if !errors.Is(err, domain.ErrRefreshTokenNotFound) {
				t.Fatalf("Parse(%q) error = %v, want ErrRefreshTokenNotFound", tt.token, err)
			}
		})
	}
}
