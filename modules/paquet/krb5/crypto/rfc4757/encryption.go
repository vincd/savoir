package rfc4757

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"fmt"
)

// https://datatracker.ietf.org/doc/html/rfc4757#section-5

func Encrypt(key []byte, data []byte) ([]byte, error) {
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error creating RC4 cipher: %s", err)
	}

	ed := make([]byte, len(data))
	copy(ed, data)
	rc4Cipher.XORKeyStream(ed, ed)
	rc4Cipher.Reset()

	return ed, nil
}

func Decrypt(key []byte, data []byte) ([]byte, error) {
	return Encrypt(key, data)
}

func EncryptMessage(key, data []byte, usage uint32) ([]byte, error) {
	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, fmt.Errorf("Error generating confounder: %s", err)
	}

	ki := HMAC(key, usageToMessageType(usage))
	cksum := HMAC(ki, append(confounder, data...))
	ke := HMAC(ki, cksum)

	e, err := Encrypt(ke, append(confounder, data...))
	if err != nil {
		return []byte{}, fmt.Errorf("error encrypting data: %v", err)
	}

	return append(cksum, e...), nil
}

func DecryptMessage(key []byte, data []byte, usage uint32) ([]byte, error) {
	if len(data) < 24 {
		return nil, fmt.Errorf("Cipher text is too short")
	}

	cksum := data[:16]
	cipherText := data[16:]

	ki := HMAC(key, usageToMessageType(usage))
	ke := HMAC(ki, cksum)

	plainText, err := Decrypt(ke, cipherText)
	if err != nil {
		return nil, err
	}

	expCksum := HMAC(ki, plainText)
	ok := hmac.Equal(expCksum, cksum)

	if !ok && usage == 9 {
		// Try again with usage 8, due to RFC 4757 errata.
		ki = HMAC(key, usageToMessageType(8))
		expCksum := HMAC(ki, plainText)
		ok = hmac.Equal(expCksum, cksum)
	}

	if !ok {
		return nil, fmt.Errorf("Error checking data integrity")
	}

	return plainText[8:], nil
}
