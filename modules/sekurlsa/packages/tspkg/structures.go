package tspkg

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils/binary"
)

type KiwiTsPrimaryCredential struct {
	Unk0        binary.Pointer
	Credentials globals.KiwiGenericPrimaryCredential
}

type KiwiTsCredential struct {
	// Unk0                    [108]byte on AMD64 or [64]byte on x86
	Unk0_1                  binary.Pointer
	Unk0_2                  binary.Pointer
	Unk0_3                  binary.Pointer
	Unk0_4                  binary.Pointer
	Unk0_5                  binary.Pointer
	Unk0_6                  binary.Pointer
	Unk0_7                  binary.Pointer
	Unk0_8                  binary.Pointer
	Unk0_9                  binary.Pointer
	Unk0_10                 binary.Pointer
	Unk0_11                 binary.Pointer
	Unk0_12                 uint32
	Unk0_13                 uint32
	Unk0_14                 uint32
	Unk0_15                 uint32
	Unk0_16                 uint32
	LocallyUniqueIdentifier uint64
	_                       uint32
	Unk1                    binary.Pointer
	Unk2                    binary.Pointer
	TsPrimary               binary.Pointer
}

type KiwiTsCredential1607 struct {
	//Unk0                    [112]byte on AMD64 or [68]byte on x86
	Unk0_1                  binary.Pointer
	Unk0_2                  binary.Pointer
	Unk0_3                  binary.Pointer
	Unk0_4                  binary.Pointer
	Unk0_5                  binary.Pointer
	Unk0_6                  binary.Pointer
	Unk0_7                  binary.Pointer
	Unk0_8                  binary.Pointer
	Unk0_9                  binary.Pointer
	Unk0_10                 binary.Pointer
	Unk0_11                 binary.Pointer
	Unk0_12                 uint32
	Unk0_13                 uint32
	Unk0_14                 uint32
	Unk0_15                 uint32
	Unk0_16                 uint32
	Unk0_17                 uint32
	LocallyUniqueIdentifier uint64
	_                       uint32
	Unk1                    binary.Pointer
	Unk2                    binary.Pointer
	TsPrimary               binary.Pointer
}
