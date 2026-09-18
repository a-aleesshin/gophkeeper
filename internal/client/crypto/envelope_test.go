package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func testKey(seed byte) Key {
	var key Key
	for i := range key {
		key[i] = seed
	}
	return key
}

func TestEnvelopeRoundtrip(t *testing.T) {
	// Arrange
	key := testKey(1)
	plaintext := []byte("credentials payload")
	aad := []byte("credentials")

	// Act
	envelope, err := Seal(key, plaintext, aad)

	// Assert
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(envelope, plaintext) {
		t.Fatal("envelope contains plaintext")
	}
	got, err := Open(key, envelope, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open = %q, want %q", got, plaintext)
	}
}

func TestEnvelopeUniqueNonce(t *testing.T) {
	// Arrange
	key := testKey(1)
	plaintext := []byte("same payload")

	// Act
	first, err := Seal(key, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	second, err := Seal(key, plaintext, nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Assert
	if bytes.Equal(first, second) {
		t.Fatal("two seals of same plaintext are identical")
	}
}

func TestEnvelopeOpenFailures(t *testing.T) {
	// Arrange
	key := testKey(1)
	envelope, err := Seal(key, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 0xFF

	wrongVersion := append([]byte(nil), envelope...)
	wrongVersion[0] = 0x02

	tests := []struct {
		name     string
		key      Key
		envelope []byte
		aad      []byte
		wantErr  error
	}{
		{name: "wrong key", key: testKey(2), envelope: envelope, aad: []byte("aad"), wantErr: ErrDecryptionFailed},
		{name: "wrong aad", key: key, envelope: envelope, aad: []byte("other"), wantErr: ErrDecryptionFailed},
		{name: "tampered ciphertext", key: key, envelope: tampered, aad: []byte("aad"), wantErr: ErrDecryptionFailed},
		{name: "unsupported version", key: key, envelope: wrongVersion, aad: []byte("aad"), wantErr: ErrUnsupportedEnvelope},
		{name: "empty", key: key, envelope: nil, aad: nil, wantErr: ErrMalformedEnvelope},
		{name: "truncated", key: key, envelope: envelope[:10], aad: []byte("aad"), wantErr: ErrMalformedEnvelope},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			_, err := Open(tt.key, tt.envelope, tt.aad)

			// Assert
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Open error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
