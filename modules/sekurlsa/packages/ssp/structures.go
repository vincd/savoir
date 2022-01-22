package ssp

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils/binary"
)

type KiwiSSPCredentialListEntry struct {
	Flink                binary.Pointer
	Blink                binary.Pointer
	References           uint32
	CredentialReferences uint32
	LogonId              uint64
	Unk0                 uint32
	Unk1                 uint32
	Unk2                 uint32
	_                    uint32
	Credentials          globals.KiwiGenericPrimaryCredential
}
