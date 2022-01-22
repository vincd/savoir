package krb5

import (
	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.8
// We dont create a custom type because the asn1 lib does not handle correctly
// redefined types
func NewKerberosFlags() asn1.BitString {
	return NewKerberosFlagsFromUInt32(0)
}

func NewKerberosFlagsFromUInt32(f uint32) asn1.BitString {
	flags := asn1.BitString{}
	flags.Bytes = []byte{
		byte(f & 0xFF000000 >> 24),
		byte(f & 0x00FF0000 >> 16),
		byte(f & 0x0000FF00 >> 8),
		byte(f & 0x000000FF >> 0),
	}
	flags.BitLength = 4 * 8

	return flags
}

func SetKerberosFlag(kFlags *asn1.BitString, flag int) {
	// Get the byte index in the array
	i := flag / 8
	// Get the bit in the current byte
	p := uint(7 - (flag - 8*i))
	// Set the bit the flags
	kFlags.Bytes[i] = kFlags.Bytes[i] | (1 << p)
}

func Uint32ToKerberosFlags(f uint32) asn1.BitString {
	flags := asn1.BitString{}
	flags.Bytes = []byte{
		byte(f & 0xFF000000 >> 24),
		byte(f & 0x00FF0000 >> 16),
		byte(f & 0x0000FF00 >> 8),
		byte(f & 0x000000FF >> 0),
	}
	flags.BitLength = len(flags.Bytes) * 8

	return flags
}
