package windows

import (
	"fmt"
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (guid GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", guid.Data1, guid.Data2, guid.Data3, guid.Data4[:2], guid.Data4[2:])
}
