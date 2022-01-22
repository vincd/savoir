package process

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")
	procQueryFullProcessImageNameW = modkernel32.NewProc("QueryFullProcessImageNameW")
)

func FindProcessWithName(processName string) (*windows.ProcessEntry32, error) {
	processes, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}

	processEntry := &windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}

	for err = windows.Process32First(processes, processEntry); err == nil; err = windows.Process32Next(processes, processEntry) {
		if strings.ToLower(windows.UTF16ToString(processEntry.ExeFile[:])) == processName {
			return processEntry, nil
		}
	}

	return nil, fmt.Errorf("Could not find process with name %s.", processName)
}

/*func QueryFullProcessImageNameW(handle windows.Handle, dwFlags uint32, buffer *byte, length *uint32) (ok bool) {
	r0, _, _ := syscall.Syscall6(procQueryFullProcessImageNameW.Addr(), 4, uintptr(handle), uintptr(dwFlags), uintptr(unsafe.Pointer(buffer)), uintptr(unsafe.Pointer(length)), 0, 0)
	ok = r0 != 0
	return
}*/

func QueryFullProcessImageName(handle windows.Handle, dwFlags uint32) (string, error) {
	var size uint32 = syscall.MAX_PATH
	buffer := make([]uint16, size)

	r0, _, _ := syscall.Syscall6(procQueryFullProcessImageNameW.Addr(), 4, uintptr(handle), uintptr(dwFlags), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, 0)
	if r0 != 0 {
		return syscall.UTF16ToString(buffer), nil
	}

	return "", fmt.Errorf("Could not query full image name.")
}
