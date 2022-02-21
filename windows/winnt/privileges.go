//go:build windows
// +build windows

package winnt

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	procLookupPrivilegeNameW = modadvapi32.NewProc("LookupPrivilegeNameW")
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

func (luid LUID) String() string {
	return fmt.Sprintf("LUID(0x%x, 0x%x)", luid.HighPart, luid.LowPart)
}

func LookupPrivilegeName(systemName *uint16, luid *LUID, buffer *uint16, size *uint32) error {
	r1, _, e1 := syscall.Syscall6(procLookupPrivilegeNameW.Addr(), 4, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(luid)), uintptr(unsafe.Pointer(buffer)), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		return e1
	}

	return nil
}
