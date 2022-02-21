//go:build windows
// +build windows

package kernel32

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
)

func ReadProcessMemory(handle windows.Handle, address uintptr, size uint64) ([]byte, error) {
	nbr := uintptr(0)
	data := make([]byte, size)

	r0, _, e1 := procReadProcessMemory.Call(
		uintptr(handle),
		uintptr(address),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&nbr)))

	if r0 == 0 {
		if e1 != nil {
			return nil, e1
		}
		return nil, syscall.EINVAL
	}

	return data, nil
}

func QueryFullProcessImageName(handle windows.Handle, dwFlags uint32) (string, error) {
	var size uint32 = syscall.MAX_PATH
	buffer := make([]uint16, size)

	r0, _, _ := syscall.Syscall6(procQueryFullProcessImageNameW.Addr(), 4, uintptr(handle), uintptr(dwFlags), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	if r0 != 0 {
		return syscall.UTF16ToString(buffer), nil
	}

	return "", fmt.Errorf("Could not query full image name.")
}
