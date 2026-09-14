package valueobject

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestParseUserID(t *testing.T) {
	// Arrange
	valid := uuid.Must(uuid.NewV7())
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "valid uuid v7", input: valid.String(), want: valid.String()},
		{name: "valid uuid v4", input: "f47ac10b-58cc-4372-a567-0e02b2c3d479", want: "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
		{name: "nil uuid", input: "00000000-0000-0000-0000-000000000000", wantErr: ErrInvalidUserID},
		{name: "empty", input: "", wantErr: ErrInvalidUserID},
		{name: "garbage", input: "not-a-uuid", wantErr: ErrInvalidUserID},
		{name: "truncated", input: "f47ac10b-58cc-4372-a567", wantErr: ErrInvalidUserID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := ParseUserID(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseUserID(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseUserID(%q) unexpected error: %v", tt.input, err)
			}

			if got.String() != tt.want {
				t.Fatalf("ParseUserID(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}

			if got.IsZero() {
				t.Fatalf("ParseUserID(%q).IsZero() = true, want false", tt.input)
			}
		})
	}
}

func TestUserIDFromUUID(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		input   uuid.UUID
		wantErr error
	}{
		{name: "valid", input: uuid.Must(uuid.NewV7())},
		{name: "nil", input: uuid.Nil, wantErr: ErrInvalidUserID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := UserIDFromUUID(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("UserIDFromUUID error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("UserIDFromUUID unexpected error: %v", err)
			}

			if got.UUID() != tt.input {
				t.Fatalf("UUID() = %v, want %v", got.UUID(), tt.input)
			}
		})
	}
}

func TestUserIDZeroValue(t *testing.T) {
	// Arrange
	var id UserID

	// Act
	zero := id.IsZero()

	// Assert
	if !zero {
		t.Fatal("zero UserID: IsZero() = false, want true")
	}
}
