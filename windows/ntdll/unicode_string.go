package ntdll

import (
	"reflect"
	"unicode/utf16"
	"unsafe"
)

// UnicodeString has been derived from the UNICODE_STRING struct definition.
type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// String converts the UTF-16-encoded string stored in a UnicodeString
// to UTF-8 and returns that as a Go string.
func (u UnicodeString) String() string {
	var s []uint16
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(u.Buffer))
	hdr.Len = int(u.Length / 2)
	hdr.Cap = int(u.MaximumLength / 2)
	return string(utf16.Decode(s))
}

// NewUnicodeString converts its argument to UTF-16 and returns a
// pointer to a UnicodeString that can be used with various Windows
// Native API functions.
func NewUnicodeString(s string) *UnicodeString {
	buf := utf16.Encode([]rune(s))
	return &UnicodeString{
		Length:        uint16(2 * len(buf)),
		MaximumLength: uint16(2 * len(buf)),
		Buffer:        &buf[0],
	}
}
