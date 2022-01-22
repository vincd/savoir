package rfc3961

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"
)

func getHash(eType EncryptionType, key []byte, plainText []byte) []byte {
	h := hmac.New(eType.GetHashFunc(), key)
	h.Write(plainText)
	mac := h.Sum(nil)

	return mac[:eType.GetHmacSize()]
}

func EncryptMessage(et EncryptionType, key []byte, clearMessage []byte, usage uint32) ([]byte, error) {
	confounder := make([]byte, et.GetCipherBlockSize())
	_, err := rand.Read(confounder)
	if err != nil {
		return nil, fmt.Errorf("Cannot generate random confounder: %s", err)
	}

	// Ke = DK(base-key, usage | 0xAA);
	ke, err := DeriveKey(key, GetWellKnowConstant(usage, KeOctet), et)
	if err != nil {
		return nil, err
	}

	// Ki = DK(base-key, usage | 0x55);
	ki, err := DeriveKey(key, GetWellKnowConstant(usage, KiOctet), et)
	if err != nil {
		return nil, err
	}

	plainText := append(confounder, clearMessage...)
	cipherText, err := et.Encrypt(ke, plainText)
	if err != nil {
		return nil, err
	}

	mac := getHash(et, ki, plainText)

	return append(cipherText, mac...), nil
}

func DecryptMessage(et EncryptionType, key []byte, encryptedMessage []byte, usage uint32) ([]byte, error) {
	// Ke = DK(base-key, usage | 0xAA);
	ke, err := DeriveKey(key, GetWellKnowConstant(usage, KeOctet), et)
	if err != nil {
		return nil, err
	}

	// Ki = DK(base-key, usage | 0x55);
	ki, err := DeriveKey(key, GetWellKnowConstant(usage, KiOctet), et)
	if err != nil {
		return nil, err
	}

	// Separate message [cipherText|checksum]
	checksum := encryptedMessage[len(encryptedMessage)-et.GetHmacSize():]
	ciphertext := encryptedMessage[:len(encryptedMessage)-et.GetHmacSize()]

	plainText, err := et.Decrypt(ke, ciphertext)
	if err != nil {
		return nil, err
	}

	// Calculte checksum
	mac := getHash(et, ki, plainText)
	if !hmac.Equal(mac, checksum) {
		return nil, fmt.Errorf("Invalid checksum on decrypted data")
	}

	// Remove first block (confondeur)
	return plainText[et.GetCipherBlockSize():], nil
}
