package rfc4757

import (
	"bytes"
	"io"

	"golang.org/x/crypto/md4"
	"golang.org/x/text/encoding/unicode"
)

// https://datatracker.ietf.org/doc/html/rfc4757

func StringToKey(password string) ([]byte, error) {
	// K = MD4(UNICODE(password))

	utf16le := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	utfEncoder := utf16le.NewEncoder()
	b, err := utfEncoder.Bytes([]byte(password))
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)
	h := md4.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
