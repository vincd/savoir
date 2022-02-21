package luid

import (
	"fmt"
	"syscall"

	"github.com/vincd/savoir/windows/winnt"
)

const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
	SE_PRIVILEGE_VALID_ATTRIBUTES   = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED | SE_PRIVILEGE_USED_FOR_ACCESS
)

type LUIDAndAttributes struct {
	Luid       winnt.LUID
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

	name, err := LookupPrivilegeName("", &s.Luid)
	if err != nil {
		o += fmt.Sprintf("{Luid=%s}", s.Luid.String())
	} else {
		o += fmt.Sprintf("%s", name)
	}

	return o
}

func LookupPrivilegeName(systemName string, luid *winnt.LUID) (string, error) {
	buf := make([]uint16, 256)
	bufSize := uint32(len(buf))

	systemNameUtf16, err := syscall.UTF16PtrFromString(systemName)
	if err != nil {
		return "", fmt.Errorf("cannot convert to UTF16 SystemName %s: %s", systemName, err)
	}

	if err := winnt.LookupPrivilegeName(systemNameUtf16, luid, &buf[0], &bufSize); err != nil {
		return "", fmt.Errorf("LookupPrivilegeName failed for luid=%v: %s", luid, err)
	}

	return syscall.UTF16ToString(buf), nil
}
