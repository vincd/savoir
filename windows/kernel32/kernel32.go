//go:build windows
// +build windows

package kernel32

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
)

var (
	procGetModuleFileNameEx = modkernel32.NewProc("K32GetModuleFileNameExW")
	procGetSystemInfo       = modkernel32.NewProc("GetSystemInfo")
	procVirtualQueryEx      = modkernel32.NewProc("VirtualQueryEx")
)

type SystemInfo struct {
	ProcessorArchitecture     uint32
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uint
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type MemoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func VirtualQueryEx(process windows.Handle, address uintptr) (*MemoryBasicInfo, error) {
	var buffer MemoryBasicInfo

	r0, _, e1 := procVirtualQueryEx.Call(
		uintptr(process),
		address,
		uintptr(unsafe.Pointer(&buffer)),
		unsafe.Sizeof(buffer),
	)

	if r0 == 0 {
		if e1 != nil {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}

	return &buffer, nil
}

func GetSystemInfo() SystemInfo {
	var info SystemInfo
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(&info)))

	return info
}

func GetModuleFilenameEx(process windows.Handle, module windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	err := _GetModuleFileNameEx(process, module, &buf[0], uint32(len(buf)))
	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf), nil
}

func _GetModuleFileNameEx(hProcess windows.Handle, hModule windows.Handle, data *uint16, nSize uint32) (err error) {
	r0, _, err := procGetModuleFileNameEx.Call(uintptr(hProcess), uintptr(hModule), uintptr(unsafe.Pointer(data)), uintptr(nSize))
	if r0 == 0 {
		return err
	}

	return nil
}
