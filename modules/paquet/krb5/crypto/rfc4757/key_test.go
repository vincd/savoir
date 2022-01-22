package rfc4757

import (
	"bytes"
	"testing"
)

// https://datatracker.ietf.org/doc/html/rfc4757#section-2
func TestStringToKey(t *testing.T) {
	// For an account with a password of "foo", this String2Key("foo") will
	// return:

	// 0xac, 0x8e, 0x65, 0x7f, 0x83, 0xdf, 0x82, 0xbe,
	// 0xea, 0x5d, 0x43, 0xbd, 0xaf, 0x78, 0x00, 0xcc

	password := "foo"
	key := []byte{0xac, 0x8e, 0x65, 0x7f, 0x83, 0xdf, 0x82, 0xbe, 0xea, 0x5d, 0x43, 0xbd, 0xaf, 0x78, 0x00, 0xcc}

	k, err := StringToKey(password)
	if err != nil {
		t.Fatalf("Error gettin StringToKey: %s", err)
	}

	if bytes.Compare(key, k) != 0 {
		t.Errorf("Key is not correct: %x vs %x.", key, k)
	}
}
