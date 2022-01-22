package wdigest

import (
	"github.com/vincd/savoir/utils/binary"
)

type KiwiWDigestListEntry struct {
	Flink      binary.Pointer
	Blink      binary.Pointer
	UsageCount uint32
	_          uint32
	This       binary.Pointer
	LUID       uint64
}
