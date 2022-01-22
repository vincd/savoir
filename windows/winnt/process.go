//go:build windows
// +build windows

package winnt

import (
	"strings"
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

	return r0 > 0
}

func CreateProcessWithToken(token windows.Token, commandLine string) error {
	program := commandLine
	args := ""

	i := strings.Index(commandLine, " ")
	if i > -1 {
		program = commandLine[:i]
		args = commandLine[i+1:]
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation

	status := CreateProcessWithTokenW(token, 0, windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
	if !status {
		err := windows.CreateProcessAsUser(token, windows.StringToUTF16Ptr(program), windows.StringToUTF16Ptr(args), nil, nil, false, windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
		if err != nil {
			return err
		}
	}

	return nil
}
