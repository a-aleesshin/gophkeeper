package crypto

import (
	"bytes"
	"testing"
)

func TestPayloadRoundtrip(t *testing.T) {
	// Arrange
	creds := Credentials{Login: "alice@bank.com", Password: "s3cret"}
	card := Card{Number: "4111111111111111", Holder: "ALICE SMITH", ExpMonth: 12, ExpYear: 2030, CVC: "123"}
	binary := Binary{Name: "key.pem", Data: []byte{0x00, 0x01, 0xFF}}
	text := Text{Content: "recovery codes: 1234 5678"}

	// Act + Assert
	credsData, err := EncodePayload(creds)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	gotCreds, err := DecodePayload[Credentials](credsData)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if gotCreds != creds {
		t.Fatalf("credentials = %+v, want %+v", gotCreds, creds)
	}

	cardData, err := EncodePayload(card)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	gotCard, err := DecodePayload[Card](cardData)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if gotCard != card {
		t.Fatalf("card = %+v, want %+v", gotCard, card)
	}

	binaryData, err := EncodePayload(binary)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	gotBinary, err := DecodePayload[Binary](binaryData)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if gotBinary.Name != binary.Name || !bytes.Equal(gotBinary.Data, binary.Data) {
		t.Fatalf("binary = %+v, want %+v", gotBinary, binary)
	}

	textData, err := EncodePayload(text)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	gotText, err := DecodePayload[Text](textData)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if gotText != text {
		t.Fatalf("text = %+v, want %+v", gotText, text)
	}
}

func TestDecodePayloadMalformed(t *testing.T) {
	// Act
	_, err := DecodePayload[Credentials]([]byte("not json"))

	// Assert
	if err == nil {
		t.Fatal("DecodePayload accepted malformed data")
	}
}

func TestEncryptedPayloadEndToEnd(t *testing.T) {
	// Arrange
	secrets := Derive("alice", "correct horse battery")
	creds := Credentials{Login: "alice@bank.com", Password: "s3cret"}

	// Act
	plain, err := EncodePayload(creds)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	envelope, err := Seal(secrets.EncryptionKey, plain, []byte("credentials"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := Open(secrets.EncryptionKey, envelope, []byte("credentials"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := DecodePayload[Credentials](opened)
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}

	// Assert
	if got != creds {
		t.Fatalf("roundtrip = %+v, want %+v", got, creds)
	}
	if bytes.Contains(envelope, []byte("s3cret")) || bytes.Contains(envelope, []byte("alice@bank.com")) {
		t.Fatal("envelope leaks plaintext fields")
	}
}
