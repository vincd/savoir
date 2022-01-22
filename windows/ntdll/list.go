package ntdll

import (
	"github.com/vincd/savoir/utils/binary"
)

type ListEntry struct {
	Flink binary.Pointer
	Blink binary.Pointer
}
