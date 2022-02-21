//go:build windows
// +build windows

package windows

import (
	"fmt"
	"strings"
	"unsafe"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/windows/tokens"
	"github.com/vincd/savoir/windows/winnt"
)

// Find a process by this name and returns a `ProcessEntry32` pointer if found
// Process name is matched case insensitive
func FindProcessWithName(processName string) (*sys_windows.ProcessEntry32, error) {
	// Make process name lower to be case insensitive
	lowerProcessName := strings.ToLower(processName)

	processes, err := sys_windows.CreateToolhelp32Snapshot(sys_windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}

	processEntry := &sys_windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(sys_windows.ProcessEntry32{})),
	}

	for err := sys_windows.Process32First(processes, processEntry); err == nil; err = sys_windows.Process32Next(processes, processEntry) {
		if strings.ToLower(sys_windows.UTF16ToString(processEntry.ExeFile[:])) == lowerProcessName {
			return processEntry, nil
		}
	}

	return nil, fmt.Errorf("cannot find process with name %s", processName)
}

// Create a new process with a Token
func CreateProcessWithToken(token tokens.Token, commandLine string) error {
	program := commandLine
	args := ""

	i := strings.Index(commandLine, " ")
	if i > -1 {
		program = commandLine[:i]
		args = commandLine[i+1:]
	}

	var si sys_windows.StartupInfo
	var pi sys_windows.ProcessInformation

	status := winnt.CreateProcessWithTokenW(sys_windows.Token(token), 0, sys_windows.StringToUTF16Ptr(program), sys_windows.StringToUTF16Ptr(args), sys_windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
	if !status {
		err := sys_windows.CreateProcessAsUser(sys_windows.Token(token), sys_windows.StringToUTF16Ptr(program), sys_windows.StringToUTF16Ptr(args), nil, nil, false, sys_windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
		if err != nil {
			return err
		}
	}

	return nil
}
