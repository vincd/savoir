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

const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
	SE_PRIVILEGE_VALID_ATTRIBUTES   = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED | SE_PRIVILEGE_USED_FOR_ACCESS
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

func (luid LUID) LookupPrivilegeName(systemName string) (string, error) {
	return LookupPrivilegeName("", &luid)
}

func (luid LUID) String() string {
	return fmt.Sprintf("%x%x", luid.HighPart, luid.LowPart)
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

func (s LUIDAndAttributes) IsEnabledByDefault() bool {
	return (s.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) > 0
}

func (s LUIDAndAttributes) IsEnabled() bool {
	return (s.Attributes & SE_PRIVILEGE_ENABLED) > 0
}

func (s LUIDAndAttributes) IsRemoved() bool {
	return (s.Attributes & SE_PRIVILEGE_REMOVED) > 0
}

func (s LUIDAndAttributes) IsUsed() bool {
	return (s.Attributes & SE_PRIVILEGE_USED_FOR_ACCESS) > 0
}

func (s LUIDAndAttributes) String() string {
	o := "["

	if s.IsEnabledByDefault() {
		o += "D"
	} else {
		o += " "
	}

	if s.IsEnabled() {
		o += "E"
	} else {
		o += " "
	}

	if s.IsRemoved() {
		o += "R"
	} else {
		o += " "
	}

	if s.IsUsed() {
		o += "U"
	} else {
		o += " "
	}

	o += "] "

	name, err := s.Luid.LookupPrivilegeName("")
	if err != nil {
		o += fmt.Sprintf("{Luid=%s}", s.Luid.String())
	} else {
		o += fmt.Sprintf("%s", name)
	}

	return o
}

func LookupPrivilegeName(systemName string, luid *LUID) (string, error) {
	buf := make([]uint16, 256)
	bufSize := uint32(len(buf))
	err := _LookupPrivilegeName(systemName, luid, &buf[0], &bufSize)
	if err != nil {
		return "", fmt.Errorf("LookupPrivilegeName failed for luid=%v", luid)
	}

	return syscall.UTF16ToString(buf), nil
}

func _LookupPrivilegeName(systemName string, luid *LUID, buffer *uint16, size *uint32) (err error) {
	var _p0 *uint16
	_p0, err = syscall.UTF16PtrFromString(systemName)
	if err != nil {
		return
	}
	return __LookupPrivilegeName(_p0, luid, buffer, size)
}

func __LookupPrivilegeName(systemName *uint16, luid *LUID, buffer *uint16, size *uint32) (err error) {
	r1, _, e1 := syscall.Syscall6(procLookupPrivilegeNameW.Addr(), 4, uintptr(unsafe.Pointer(systemName)), uintptr(unsafe.Pointer(luid)), uintptr(unsafe.Pointer(buffer)), uintptr(unsafe.Pointer(size)), 0, 0)
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
