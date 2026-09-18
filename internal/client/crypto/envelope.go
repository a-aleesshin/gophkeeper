package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

const envelopeVersion = 0x01

var (
	ErrMalformedEnvelope   = errors.New("malformed envelope")
	ErrUnsupportedEnvelope = errors.New("unsupported envelope version")
	ErrDecryptionFailed    = errors.New("decryption failed")
)

func Seal(key Key, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	envelope := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	envelope = append(envelope, envelopeVersion)
	envelope = append(envelope, nonce...)
	return aead.Seal(envelope, nonce, plaintext, aad), nil
}

func Open(key Key, envelope, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	nonceSize := aead.NonceSize()
	if len(envelope) < 1+nonceSize+aead.Overhead() {
		return nil, ErrMalformedEnvelope
	}
	if envelope[0] != envelopeVersion {
		return nil, ErrUnsupportedEnvelope
	}

	nonce := envelope[1 : 1+nonceSize]
	ciphertext := envelope[1+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

func newAEAD(key Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}

	return aead, nil
}

const (
	MaxSealedPayloadSize  = 1 << 20
	MaxSealedMetadataSize = 16 << 10
)

func AADPayload(secretType string) []byte { return []byte("payload:" + secretType) }

func AADMeta() []byte { return []byte("meta") }
