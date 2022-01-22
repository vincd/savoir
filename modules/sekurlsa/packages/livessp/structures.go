package livessp

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows/ntdll"
)

type KiwiLivesspPrimaryCredential struct {
	IsSupp      uint32
	Unk0        uint32
	Credentials globals.KiwiGenericPrimaryCredential
}

type KiwiLivesspListEntry struct {
	Flink                   binary.Pointer
	Blink                   binary.Pointer
	Unk0                    binary.Pointer
	Unk1                    binary.Pointer
	Unk2                    binary.Pointer
	Unk3                    binary.Pointer
	Unk4                    uint32
	Unk5                    uint32
	Unk6                    binary.Pointer
	LocallyUniqueIdentifier uint64
	UserName                ntdll.LsaUnicodeString
	Unk7                    binary.Pointer
	SuppCreds               binary.Pointer
}
