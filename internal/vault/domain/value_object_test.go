package domain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestParseSecretID(t *testing.T) {
	// Arrange
	valid := uuid.Must(uuid.NewV7())
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{name: "valid uuid v7", input: valid.String()},
		{name: "valid uuid v4", input: "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
		{name: "nil uuid", input: "00000000-0000-0000-0000-000000000000", wantErr: ErrInvalidSecretID},
		{name: "empty", input: "", wantErr: ErrInvalidSecretID},
		{name: "garbage", input: "not-a-uuid", wantErr: ErrInvalidSecretID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := ParseSecretID(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseSecretID(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseSecretID(%q) unexpected error: %v", tt.input, err)
			}

			if got.String() != tt.input {
				t.Fatalf("ParseSecretID(%q) = %q", tt.input, got.String())
			}
		})
	}
}

func TestParseSecretType(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		input   string
		want    SecretType
		wantErr error
	}{
		{name: "credentials", input: "credentials", want: SecretTypeCredentials},
		{name: "text", input: "text", want: SecretTypeText},
		{name: "binary", input: "binary", want: SecretTypeBinary},
		{name: "card", input: "card", want: SecretTypeCard},
		{name: "empty", input: "", wantErr: ErrUnknownSecretType},
		{name: "unknown", input: "totp", wantErr: ErrUnknownSecretType},
		{name: "case sensitive", input: "Credentials", wantErr: ErrUnknownSecretType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := ParseSecretType(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseSecretType(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseSecretType(%q) unexpected error: %v", tt.input, err)
			}

			if got != tt.want {
				t.Fatalf("ParseSecretType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewPayload(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "valid", input: []byte("ciphertext")},
		{name: "max size", input: make([]byte, MaxPayloadSize)},
		{name: "empty", input: nil, wantErr: ErrEmptyPayload},
		{name: "too large", input: make([]byte, MaxPayloadSize+1), wantErr: ErrPayloadTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewPayload(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewPayload error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewPayload unexpected error: %v", err)
			}

			if !bytes.Equal(got.Bytes(), tt.input) {
				t.Fatal("Bytes() does not match input")
			}
		})
	}
}

func TestPayloadImmutability(t *testing.T) {
	// Arrange
	raw := []byte("ciphertext")
	p, err := NewPayload(raw)
	if err != nil {
		t.Fatalf("NewPayload: %v", err)
	}

	// Act
	raw[0] = 'X'
	leaked := p.Bytes()
	leaked[1] = 'Y'

	// Assert
	if string(p.Bytes()) != "ciphertext" {
		t.Fatalf("Payload mutated through shared slice: %q", p.Bytes())
	}
}

func TestNewMetadata(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{name: "valid", input: []byte("encrypted-meta")},
		{name: "empty allowed", input: nil},
		{name: "max size", input: make([]byte, MaxMetadataSize)},
		{name: "too large", input: make([]byte, MaxMetadataSize+1), wantErr: ErrMetadataTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewMetadata(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewMetadata error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewMetadata unexpected error: %v", err)
			}

			if !bytes.Equal(got.Bytes(), tt.input) {
				t.Fatal("Bytes() does not match input")
			}
		})
	}
}
