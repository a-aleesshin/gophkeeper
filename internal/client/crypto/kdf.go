package crypto

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

const (
	kdfTime    = 3
	kdfMemory  = 64 * 1024
	kdfThreads = 4
	keyLen     = 32

	encContext  = "gophkeeper/v1/kdf/enc:"
	authContext = "gophkeeper/v1/kdf/auth:"
)

type Key [keyLen]byte

type DerivedSecrets struct {
	EncryptionKey Key
	AuthPassword  string
}

func Derive(login, masterPassword string) DerivedSecrets {
	encKey := derive(encContext, login, masterPassword)
	authKey := derive(authContext, login, masterPassword)

	var key Key
	copy(key[:], encKey)

	return DerivedSecrets{
		EncryptionKey: key,
		AuthPassword:  base64.RawURLEncoding.EncodeToString(authKey),
	}
}

func derive(context, login, masterPassword string) []byte {
	salt := sha256.Sum256([]byte(context + login))
	return argon2.IDKey([]byte(masterPassword), salt[:], kdfTime, kdfMemory, kdfThreads, keyLen)
}
