package ntdll

import (
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
)

type LsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             uint32
	BufferPointer binary.Pointer
}

func (s *LsaUnicodeString) ReadBytes(r utils.MemoryReader) ([]byte, error) {
	if s.BufferPointer == 0 {
		return nil, nil
	}

	chunk, err := r.Read(s.BufferPointer, uint32(s.MaximumLength))
	if err != nil {
		return nil, err
	}

	return chunk, nil
}

func (s *LsaUnicodeString) ReadString(r utils.MemoryReader) (string, error) {
	chunk, err := s.ReadBytes(r)
	if err != nil {
		return "", err
	}

	decodedString, err := utils.UTF16DecodeFromBytes(chunk)
	if err != nil {
		return "", err
	}

	// Remove NULL bytes at the end of the string
	for len(decodedString) > 0 && decodedString[len(decodedString)-1] == byte(0) {
		decodedString = decodedString[:len(decodedString)-1]
	}

	return decodedString, nil
}

func GetLsaUnicodeStringValue(r utils.MemoryReader, ptr binary.Pointer) (string, error) {
	l := &LsaUnicodeString{}
	if err := r.ReadStructure(ptr, l); err != nil {
		return "", err
	}

	v, err := l.ReadString(r)
	if err != nil {
		return "", err
	}

	return v, nil
}

func GetLsaUnicodeBytesValue(r utils.MemoryReader, ptr binary.Pointer) ([]byte, error) {
	l := &LsaUnicodeString{}
	if err := r.ReadStructure(ptr, l); err != nil {
		return nil, err
	}

	v, err := l.ReadBytes(r)
	if err != nil {
		return nil, err
	}

	return v, nil
}
