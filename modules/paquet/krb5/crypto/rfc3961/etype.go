package rfc3961

import (
	"hash"
)

type EncryptionType interface {
	GetEtype() int32
	GetHashFunc() func() hash.Hash
	GetHmacSize() int
	GetCipherBlockSize() int
	Encrypt([]byte, []byte) ([]byte, error)
	EncryptMessage([]byte, []byte, uint32) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
	DecryptMessage([]byte, []byte, uint32) ([]byte, error)
	GetSecretKeySize() int
	GenerateSecretkey(string, string, string) ([]byte, error)
}
