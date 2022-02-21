//go:build windows
// +build windows

package x86matthew

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/kernel32"
	// "github.com/vincd/savoir/windows/ntdll"
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	}
	return e
}


var (
	modntdll = windows.NewLazySystemDLL("ntdll.dll")

	procRtlFirstEntrySList    = modntdll.NewProc("RtlFirstEntrySList")
	procNtCreateThreadEx = modntdll.NewProc("NtCreateThreadEx")
)

func NtCreateThreadEx(hThread *windows.Handle, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr) (uintptr) {
	r1, _, _ := syscall.Syscall12(procNtCreateThreadEx.Addr(), 11, uintptr(unsafe.Pointer(hThread)), uintptr(desiredaccess), uintptr(objattrib), uintptr(processhandle), uintptr(lpstartaddr), uintptr(lpparam), uintptr(createsuspended), uintptr(zerobits), uintptr(sizeofstack), uintptr(sizeofstackreserve), uintptr(lpbytesbuffer), 0)

	return r1
}


// Reading remote process single byte without using ReadProcessMemory
// Source: https://www.x86matthew.com/view_post?id=read_write_proc_memory
func ReadProcessMemoryByte(hProcess windows.Handle, address uintptr, pValue *byte) error {
	// find RtlFirstEntrySList ptr in ntdll
	// modntdll := windows.NewLazyDLL("ntdll")
	// procRtlFirstEntrySList := modntdll.NewProc("RtlFirstEntrySList")

	// create remote thread
	var hThread windows.Handle
	if status := NtCreateThreadEx(&hThread, 0x001FFFFF, 0, uintptr(hProcess), procRtlFirstEntrySList.Addr(), address, 0, 0, 0, 0, 0); status != 0 {
		return fmt.Errorf("ReadProcessMemoryByte cannot create remote thread: %s", status)
	}
	// close thread handle
	defer windows.CloseHandle(hThread)

	// wait for RtlFirstEntrySList to return
	event, err := syscall.WaitForSingleObject(syscall.Handle(hThread), syscall.INFINITE)
	if err != nil {
		return fmt.Errorf("ReadProcessMemoryByte cannot wait for thread: %s", err)
	}

	if event != syscall.WAIT_OBJECT_0 {
		return fmt.Errorf("ReadProcessMemoryByte WaitForSingleObject returns wrong event: %+v", event)
	}

	// get exit code (this contains the RtlFirstEntrySList return value)
	dwExitCode := uint32(0)
	if err := kernel32.GetExitCodeThread(hThread, &dwExitCode); err != nil {
		return fmt.Errorf("ReadProcessMemoryByte cannot get thread exit code: %s", err)
	}

	fmt.Printf("Read byte: 0x%x -> dwExitCode: 0x%x\n", address, dwExitCode)

	// store output value
	*pValue = byte(dwExitCode & 0xFF)

	return nil
}

// Reading remote process data without using ReadProcessMemory
// Source: https://www.x86matthew.com/view_post?id=read_write_proc_memory
func ReadProcessMemory(hProcess windows.Handle, address uintptr, size uint64) ([]byte, error) {
	data := make([]byte, size)
	fmt.Printf("procRtlFirstEntrySList: 0x%x\n", procRtlFirstEntrySList.Addr())
	bb, err := kernel32.ReadProcessMemory(hProcess, procRtlFirstEntrySList.Addr()-uintptr(0x10), 0x20)
	if err != nil {
		return nil, fmt.Errorf("DEBUG: %s", err)
	}

	fmt.Printf("%x\n", bb)
	fmt.Printf("procNtCreateThreadEx: 0x%x\n", procNtCreateThreadEx.Addr())

	for i := uint64(0); i < size; i++ {
		if err := ReadProcessMemoryByte(hProcess, address+uintptr(i), &data[i]); err != nil {
			return nil, fmt.Errorf("ReadProcessMemory cannot read byte at 0x%x + 0x%x: %s", address, i, err)
		}
	}

	return data, nil
}
