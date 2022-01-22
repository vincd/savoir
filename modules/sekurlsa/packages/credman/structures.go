package credman

import (
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows/ntdll"
)

type KiwiCredmanSetListEntry struct {
	Flink binary.Pointer
	Blink binary.Pointer
	Unk0  uint32
	_     uint32
	List1 binary.Pointer
	List2 binary.Pointer
}

type KiwiCredmanListStarter struct {
	Unk0  uint32
	_     uint32
	Start binary.Pointer
}

type KiwiCredmanListEntry5 struct {
	EncPasswordLength uint32
	_                 uint32
	EncPassword       binary.Pointer
	Unk0              uint32
	Unk1              uint32
	Unk2              binary.Pointer
	Unk3              binary.Pointer
	UserName          binary.Pointer
	CbUserName        uint32
	_                 uint32
	Flink             binary.Pointer
	Blink             binary.Pointer
	Server1           ntdll.LsaUnicodeString
	Unk6              binary.Pointer
	Unk7              binary.Pointer
	User              ntdll.LsaUnicodeString
	Unk11             uint32
	_                 uint32
	Server2           ntdll.LsaUnicodeString
}

type KiwiCredmanListEntry60 struct {
	EncPasswordLength uint32
	_                 uint32
	EncPassword       binary.Pointer
	Unk0              uint32
	Unk1              uint32
	Unk2              binary.Pointer
	Unk3              binary.Pointer
	UserName          binary.Pointer
	CbUserName        uint32
	_                 uint32
	Flink             binary.Pointer
	Blink             binary.Pointer
	Type              ntdll.LsaUnicodeString
	Unk5              binary.Pointer
	Server1           ntdll.LsaUnicodeString
	Unk6              binary.Pointer
	Unk7              binary.Pointer
	Unk8              binary.Pointer
	Unk9              binary.Pointer
	Unk10             binary.Pointer
	User              ntdll.LsaUnicodeString
	Unk11             uint32
	_                 uint32
	Server2           ntdll.LsaUnicodeString
}

type KiwiCredmanListEntry struct {
	EncPasswordLength uint32
	_                 uint32
	EncPassword       binary.Pointer
	Unk0              uint32
	Unk1              uint32
	Unk2              binary.Pointer
	Unk3              binary.Pointer
	UserName          binary.Pointer
	CbUserName        uint32
	_                 uint32
	Flink             binary.Pointer
	Blink             binary.Pointer
	Unk4              ntdll.ListEntry
	Type              ntdll.LsaUnicodeString
	Unk5              binary.Pointer
	Server1           ntdll.LsaUnicodeString
	Unk6              binary.Pointer
	Unk7              binary.Pointer
	Unk8              binary.Pointer
	Unk9              binary.Pointer
	Unk10             binary.Pointer
	User              ntdll.LsaUnicodeString
	Unk11             uint32
	_                 uint32
	Server2           ntdll.LsaUnicodeString
}
