package utils

import (
	"bytes"

	"golang.org/x/text/encoding/unicode"
)

var utf16LEDecoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()

func UTF16Decode(encodedString string) (string, error) {
	return utf16LEDecoder.String(encodedString)
}

func TrimNullBytes(s string) string {
	return string(bytes.Trim([]byte(s), "\u0000"))
}

func UTF16DecodeFromBytes(encodedBuffer []byte) (string, error) {
	return UTF16Decode(string(encodedBuffer))
}

func UTF16DecodeFromBytesWithTrim(encodedBuffer []byte) (string, error) {
	s, err := UTF16Decode(string(encodedBuffer))
	if err != nil {
		return "", err
	}

	return TrimNullBytes(s), nil
}
