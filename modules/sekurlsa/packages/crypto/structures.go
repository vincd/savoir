package crypto

import (
	"github.com/vincd/savoir/utils/binary"
)

type KiwiHardKey struct {
	CbSecret uint32
	Data     [0x18]byte // anysize
}

type KiwiBCryptKey struct {
	Size    uint32
	Tag     uint32
	Type    uint32
	Unk0    uint32
	Unk1    uint32
	Unk2    uint32
	Hardkey KiwiHardKey
}

type KiwiBCryptKey8 struct {
	Size    uint32
	Tag     uint32
	Type    uint32
	Unk0    uint32
	Unk1    uint32
	Unk2    uint32
	Unk3    uint32
	_       uint32
	Unk4    binary.Pointer
	Hardkey KiwiHardKey
}

type KiwiBCryptKey81 struct {
	Size    uint32
	Tag     uint32
	Type    uint32
	Unk0    uint32
	Unk1    uint32
	Unk2    uint32
	Unk3    uint32
	Unk4    uint32
	Unk5    binary.Pointer
	Unk6    uint32
	Unk7    uint32
	Unk8    uint32
	Unk9    uint32
	Hardkey KiwiHardKey
}

type KiwiBCryptHandleKey struct {
	Size       uint32
	Tag        uint32
	HAlgorithm binary.Pointer
	Key        binary.Pointer
	Unk0       binary.Pointer
}
