package rfc4757

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"io"
)

func usageToMessageType(usage uint32) []byte {
	switch usage {
	case 3:
		usage = 8
	case 23:
		usage = 13
	}

	b := make([]byte, 4)
	binary.PutUvarint(b, uint64(usage))

	return b
}

func Checksum(key []byte, usage uint32, data []byte) ([]byte, error) {
	// K = the Key
	// T = the message type, encoded as a little-endian four-byte integer
	// CHKSUM(K, T, data)

	// Ksign = HMAC(K, "signaturekey")  //includes zero octet at end
	Ksign := HMAC(key, []byte("signaturekey\x00"))

	// tmp = MD5(concat(T, data))
	tmp, err := MD5(append(usageToMessageType(usage), data...))
	if err != nil {
		return nil, err
	}

	// CHKSUM = HMAC(Ksign, tmp)
	CHKSUM := HMAC(Ksign, tmp)

	return CHKSUM, nil
}

func MD5(data []byte) ([]byte, error) {
	m := md5.New()
	rb := bytes.NewReader(data)
	if _, err := io.Copy(m, rb); err != nil {
		return nil, err
	}
	return m.Sum(nil), nil
}

func HMAC(key []byte, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
