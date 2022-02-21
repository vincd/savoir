package process

import (
	"fmt"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/windows/tokens"
)


type Process struct {
	handle sys_windows.Handle
}

func NewCurrentProcess() (*Process, error) {
	currentProcess, err := sys_windows.GetCurrentProcess()
	if err != nil {
		return nil, fmt.Errorf("cannot get current process handle: %s", err)
	}

	p := &Process{
		handle: currentProcess,
	}

	return p, nil
}

func NewProcessWithPid(pid uint32) (*Process, error) {
	h, err := sys_windows.OpenProcess(sys_windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}

	p := &Process{
		handle: h,
	}

	return p, nil 
}

func (p *Process) Close() {
	sys_windows.CloseHandle(p.handle)
}

func (p *Process) Handle() sys_windows.Handle {
	return p.handle
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