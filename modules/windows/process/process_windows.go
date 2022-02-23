package process

import (
	"fmt"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/windows"
	"github.com/vincd/savoir/modules/windows/tokens"
	"github.com/vincd/savoir/windows/advapi32"
	"github.com/vincd/savoir/windows/kernel32"
	"github.com/vincd/savoir/windows/psapi"
)

const (
	LogonWithProfile        uint32 = advapi32.LogonWithProfile
	LogonNetCredentialsOnly uint32 = advapi32.LogonNetCredentialsOnly
)

type Process struct {
	handle    sys_windows.Handle
	processId uint32
}

// Create a process from an handle and get its ProcessId (`GetProcessId`)
func NewProcessWithHandle(handle sys_windows.Handle) (*Process, error) {
	pid, err := sys_windows.GetProcessId(handle)
	if err != nil {
		return nil, fmt.Errorf("cannot get process id from handle: %s", err)
	}

	p := &Process{
		handle:    handle,
		processId: pid,
	}

	return p, nil
}

// Get current process handle (`GetCurrentProcess`) and get its ProcessId (`GetProcessId`)
func NewCurrentProcess() (*Process, error) {
	currentProcess, err := sys_windows.GetCurrentProcess()
	if err != nil {
		return nil, fmt.Errorf("cannot get current process handle: %s", err)
	}

	return NewProcessWithHandle(currentProcess)
}

// Find a process from its ProcessId and open it (`OpenProcess`) to get an handle
func NewProcessWithPid(pid uint32, desiredAccess uint32) (*Process, error) {
	p := &Process{
		processId: pid,
	}

	if err := p.OpenWithDesiredAccess(desiredAccess); err != nil {
		return nil, err
	}

	return p, nil
}

// Find a process `ProcessId` from its name and open it
func NewProcessWithName(processName string, desiredAccess uint32) (*Process, error) {
	// Get process ID and open it
	entry, err := windows.FindProcessWithName(processName)
	if err != nil {
		return nil, err
	}

	return NewProcessWithPid(entry.ProcessID, desiredAccess)
}

func NewProcessWithLogon(user string, domain string, password string, logonFlags uint32, cmd string, processFlags uint32) (*Process, error) {
	// Prepare arguments
	lpUsername := sys_windows.StringToUTF16Ptr(user)
	lpDomain := sys_windows.StringToUTF16Ptr(domain)
	lpPassword := sys_windows.StringToUTF16Ptr(password)
	dwLogonFlags := uint32(logonFlags)
	// lpApplicationName := sys_windows.StringToUTF16Ptr("")
	lpCommandLine := sys_windows.StringToUTF16Ptr(cmd)
	dwCreationFlags := sys_windows.CREATE_NEW_CONSOLE | processFlags
	// lpEnvironment := sys_windows.StringToUTF16Ptr("")
	/// lpCurrentDirectory := sys_windows.StringToUTF16Ptr("")
	var si sys_windows.StartupInfo
	var pi sys_windows.ProcessInformation

	if err := advapi32.CreateProcessWithLogonW(lpUsername, lpDomain, lpPassword, dwLogonFlags, nil, lpCommandLine, dwCreationFlags, nil, nil, &si, &pi); err != nil {
		return nil, fmt.Errorf("cannot create process with logon: %s", err)
	}

	p := &Process{
		handle:    pi.Process,
		processId: pi.ProcessId,
	}

	return p, nil
}

func NewProcessesFromDupHandle(processName string) ([]*Process, error) {
	processes := make([]*Process, 0)
	handles, err := windows.FindProcessHandles(processName)
	if err != nil {
		return nil, err
	}

	for _, handle := range handles {
		p, err := NewProcessWithHandle(handle)
		if err != nil {
			continue
		}

		processes = append(processes, p)
	}

	return processes, nil
}

// Get process image name (full path)
func (p *Process) FullName() string {
	processName, err := kernel32.QueryFullProcessImageName(p.Handle(), 0)
	if err != nil {
		return fmt.Sprintf("cannot get process name: %s", err)
	}

	return processName
}

func (p *Process) String() string {
	return fmt.Sprintf("Process: %s (%d)", p.FullName(), p.processId)
}

// Close process handle
func (p *Process) Close() {
	sys_windows.CloseHandle(p.handle)
}

// Get process handle
func (p *Process) Handle() sys_windows.Handle {
	return p.handle
}

// Get process Id
func (p *Process) Id() uint32 {
	return p.processId
}

func (p *Process) Reader() (*ProcessReader, error) {
	return newProcessReaderWithProcess(p)
}

// Call OpenProcess with desiredAccess then update the current handle of the process
func (p *Process) OpenWithDesiredAccess(desiredAccess uint32) error {
	newHandle, err := sys_windows.OpenProcess(desiredAccess, false, p.processId)
	if err != nil {
		return fmt.Errorf("cannot open process with pid %d and desiredAccess 0x%x: %s", p.processId, desiredAccess, err)
	}

	// Close old handle and re-set the new one
	p.Close()
	p.handle = newHandle

	return nil
}

func (p *Process) GetToken() (*tokens.Token, error) {
	return p.GetTokenWithAccess(sys_windows.TOKEN_QUERY)
}

func (p *Process) GetTokenWithAccess(access uint32) (*tokens.Token, error) {
	var token sys_windows.Token
	if err := sys_windows.OpenProcessToken(p.handle, access, &token); err != nil {
		return nil, fmt.Errorf("cannot open process token: %s", err)
	}

	t := tokens.Token(token)

	return &t, nil
}

func (p *Process) DuplicateToken(sourceToken tokens.Token, targetProcess Process) (*tokens.Token, error) {
	var duplicatedTokenHandle sys_windows.Handle
	if err := sys_windows.DuplicateHandle(p.handle, sys_windows.Handle(sys_windows.Token(sourceToken)), targetProcess.handle, &duplicatedTokenHandle, 0, false, sys_windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}

	duplicatedToken := tokens.Token(sys_windows.Token(duplicatedTokenHandle))

	return &duplicatedToken, nil
}

// Enum process modules (`EnumProcessModules` and `GetModuleInformation`)
func (p *Process) Modules() (map[string]psapi.ModuleInfo, error) {
	moduleHandles, err := windows.EnumProcessModules(p.Handle())
	if err != nil {
		return nil, err
	}

	modules := make(map[string]psapi.ModuleInfo, 0)
	for _, moduleHandle := range moduleHandles {
		moduleFilename, err := kernel32.GetModuleFilenameEx(p.Handle(), moduleHandle)
		if err != nil {
			fmt.Printf("Error on getting filename on handle: %x: %s\n", moduleHandle, err)
			continue
		}

		var mi psapi.ModuleInfo
		if err := psapi.GetModuleInformation(p.Handle(), moduleHandle, &mi); err != nil {
			fmt.Printf("Error on getting info of handle: %x: %s\n", moduleHandle, err)
			continue
		}

		modules[moduleFilename] = mi
	}

	return modules, nil
}

// Read process memory (`kernel32.ReadProcessMemory`)
func (p *Process) Read(baseAddress uintptr, size uint64) ([]byte, error) {
	data, err := kernel32.ReadProcessMemory(p.handle, baseAddress, size)
	if err != nil {
		return nil, err
	}

	return data, nil
}
