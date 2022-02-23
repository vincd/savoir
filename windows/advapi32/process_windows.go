package advapi32

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procCreateProcessWithLogonW = modadvapi32.NewProc("CreateProcessWithLogonW")
)

const (
	LogonWithProfile        uint32 = 0x00000001
	LogonNetCredentialsOnly uint32 = 0x00000002
)

func CreateProcessWithLogonW(username *uint16, domain *uint16, password *uint16, logonFlags uint32, applicationName *uint16, commandLine *uint16, creationFlags uint32, environment *uint16, currentDirectory *uint16, startupInfo *windows.StartupInfo, processInformation *windows.ProcessInformation) error {
	r0, _, err := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(environment)),
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)))

	if r0 != 0 {
		return err
	}

	return nil
}
