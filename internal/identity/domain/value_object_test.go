package domain

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestNewLogin(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{name: "valid simple", input: "alice", want: "alice"},
		{name: "normalizes case", input: "AlIcE", want: "alice"},
		{name: "trims spaces", input: "  alice  ", want: "alice"},
		{name: "allowed special chars", input: "a.li_c-e", want: "a.li_c-e"},
		{name: "starts with digit", input: "1alice", want: "1alice"},
		{name: "min length", input: "abc", want: "abc"},
		{name: "max length", input: "a" + strings.Repeat("b", 63), want: "a" + strings.Repeat("b", 63)},
		{name: "empty", input: "", wantErr: ErrInvalidLogin},
		{name: "too short", input: "ab", wantErr: ErrInvalidLogin},
		{name: "too long", input: "a" + strings.Repeat("b", 64), wantErr: ErrInvalidLogin},
		{name: "starts with dot", input: ".alice", wantErr: ErrInvalidLogin},
		{name: "starts with dash", input: "-alice", wantErr: ErrInvalidLogin},
		{name: "cyrillic", input: "алиса", wantErr: ErrInvalidLogin},
		{name: "inner space", input: "ali ce", wantErr: ErrInvalidLogin},
		{name: "special chars", input: "alice!", wantErr: ErrInvalidLogin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewLogin(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewLogin(%q) error = %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewLogin(%q) unexpected error: %v", tt.input, err)
			}

			if got.String() != tt.want {
				t.Fatalf("NewLogin(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}

			if got.IsZero() {
				t.Fatalf("NewLogin(%q).IsZero() = true, want false", tt.input)
			}
		})
	}
}

func TestLoginZeroValue(t *testing.T) {
	// Arrange
	var l Login

	// Act
	zero := l.IsZero()

	// Assert
	if !zero {
		t.Fatal("zero Login: IsZero() = false, want true")
	}
}

func TestNewPassword(t *testing.T) {
	// Arrange
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{name: "valid", input: "correct horse battery"},
		{name: "min length", input: "12345678"},
		{name: "max length", input: strings.Repeat("a", 128)},
		{name: "empty", input: "", wantErr: ErrWeakPassword},
		{name: "too short", input: "1234567", wantErr: ErrWeakPassword},
		{name: "too long", input: strings.Repeat("a", 129), wantErr: ErrWeakPassword},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			got, err := NewPassword(tt.input)

			// Assert
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("NewPassword error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewPassword unexpected error: %v", err)
			}

			if got.Reveal() != tt.input {
				t.Fatalf("Reveal() = %q, want %q", got.Reveal(), tt.input)
			}
		})
	}
}

func TestPasswordDoesNotLeakInFormatting(t *testing.T) {
	// Arrange
	const secret = "super-secret-value"
	p, err := NewPassword(secret)
	if err != nil {
		t.Fatalf("NewPassword: %v", err)
	}

	// Act
	formatted := []string{
		fmt.Sprintf("%v", p),
		fmt.Sprintf("%+v", p),
		fmt.Sprintf("%s", p),
		fmt.Sprint(p),
	}

	// Assert
	for _, out := range formatted {
		if strings.Contains(out, secret) {
			t.Fatalf("formatted output leaks password: %q", out)
		}
	}
}
