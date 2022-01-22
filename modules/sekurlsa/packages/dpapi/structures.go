package dpapi

import (
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

type KiwiMasterKeyCacheEntry struct {
	Flink      binary.Pointer
	Blink      binary.Pointer
	LogonId    uint64
	KeyUid     windows.GUID
	InsertTime windows.Filetime
	KeySize    uint32
	Key        [1]byte
}
