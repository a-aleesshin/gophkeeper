package domain

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var loginPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

type Login struct {
	value string
}

func NewLogin(s string) (Login, error) {
	normalized := strings.ToLower(strings.TrimSpace(s))
	if !loginPattern.MatchString(normalized) {
		return Login{}, ErrInvalidLogin
	}
	return Login{value: normalized}, nil
}

func RestoreLogin(s string) (Login, error) {
	if s == "" {
		return Login{}, ErrInvalidLogin
	}
	return Login{value: s}, nil
}

func (l Login) String() string { return l.value }

func (l Login) IsZero() bool { return l.value == "" }

const (
	minPasswordLen = 8
	maxPasswordLen = 128
)

type Password struct {
	value string
}

func NewPassword(s string) (Password, error) {
	if utf8.RuneCountInString(s) < minPasswordLen || len(s) > maxPasswordLen {
		return Password{}, ErrWeakPassword
	}
	return Password{value: s}, nil
}

func (p Password) Reveal() string { return p.value }

func (p Password) String() string { return "[redacted]" }

type PasswordHash struct {
	value []byte
}

func NewPasswordHash(b []byte) (PasswordHash, error) {
	if len(b) == 0 {
		return PasswordHash{}, ErrEmptyPasswordHash
	}
	return PasswordHash{value: append([]byte(nil), b...)}, nil
}

func (h PasswordHash) Bytes() []byte { return append([]byte(nil), h.value...) }

func (h PasswordHash) String() string { return "[redacted]" }

func (h PasswordHash) IsZero() bool { return len(h.value) == 0 }
