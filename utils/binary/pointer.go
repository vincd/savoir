package binary

import (
	"reflect"
)

// Add custom pointer type for structure (x86 / AMD64)
type Pointer uint64

var pointerType = reflect.TypeOf(Pointer(0))

func PointerFromBuffer(buffer []byte, is64 bool) Pointer {
	if is64 {
		return Pointer(LittleEndian.Uint64(buffer))
	} else {
		return Pointer(LittleEndian.Uint32(buffer))
	}
}

func (p Pointer) ToUint64() uint64 {
	return uint64(p)
}

func (p Pointer) U64() uint64 {
	return p.ToUint64()
}

func (p Pointer) ToInt64() int64 {
	return int64(p)
}

func (p Pointer) ToUIntPtr() uintptr {
	return uintptr(p)
}

func (p Pointer) WithOffset(offset int64) Pointer {
	// TODO: check if offset + ptr < 0 overflow
	return Pointer(p.ToInt64() + offset)
}

func (p Pointer) Lower() Pointer {
	return Pointer(uint64(p) & 0xFFFFFFFF)
}
