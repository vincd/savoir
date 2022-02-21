//go:build windows
// +build windows

package winnt

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	createProcessWithTokenW = modadvapi32.NewProc("CreateProcessWithTokenW")
)

func CreateProcessWithTokenW(Token windows.Token,
	LogonFlags uint32,
	ApplicationName *uint16,
	CommandLine *uint16,
	CreationFlags uint32,
	Environment **uint16,
	CurrentDirectory *uint16,
	StartupInfo *windows.StartupInfo,
	ProcessInformation *windows.ProcessInformation) bool {

	r0, _, _ := createProcessWithTokenW.Call(
		uintptr(Token),
		uintptr(LogonFlags),
		uintptr(unsafe.Pointer(ApplicationName)),
		uintptr(unsafe.Pointer(CommandLine)),
		uintptr(CreationFlags),
		uintptr(unsafe.Pointer(Environment)),
		uintptr(unsafe.Pointer(CurrentDirectory)),
		uintptr(unsafe.Pointer(StartupInfo)),
		uintptr(unsafe.Pointer(ProcessInformation)))

	return r0 != 0
}
