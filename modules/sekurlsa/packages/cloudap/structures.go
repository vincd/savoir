package cloudap

import (
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
	"github.com/vincd/savoir/windows/ntdll"
)

type KiwiCloudApCacheUnk struct {
	Unk0    uint32
	Unk1    uint32
	Unk2    uint32
	UnkSize uint32
	Guid    windows.GUID
	Unk     [64]byte
}

type KiwiCloudApCacheListEntry struct {
	Link        ntdll.ListEntry
	Unk0        uint32
	_           uint32
	LockList    binary.Pointer
	Unk1        binary.Pointer
	Unk2        binary.Pointer
	Unk3        binary.Pointer
	Unk4        binary.Pointer
	Unk5        binary.Pointer
	Unk6        uint32
	Unk7        uint32
	Unk8        uint32
	Unk9        uint32
	UnkLogin0   binary.Pointer
	UnkLogin1   binary.Pointer
	ToName      [64 + 1]uint16
	_           uint32
	Sid         binary.Pointer
	Unk10       uint32
	Unk11       uint32
	Unk12       uint32
	Unk13       uint32
	ToDetermine binary.Pointer
	Unk14       binary.Pointer
	CbPRT       uint32
	_           uint32
	PRT         binary.Pointer
}

type KiwiCloudApLogonListEntry struct {
	Link                    ntdll.ListEntry
	Unk0                    uint32
	Unk1                    uint32
	LocallyUniqueIdentifier uint64
	Unk2                    uint64
	Unk3                    uint64
	CacheEntry              binary.Pointer
}
