package threads

import (
	"fmt"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/windows/tokens"
)


type Thread struct {
	handle sys_windows.Handle
}

func NewCurrentThread() (*Thread, error) {
	currentThread, err := sys_windows.GetCurrentThread()
	if err != nil {
		return nil, fmt.Errorf("cannot get current thread handle: %s", err)
	}

	t := &Thread{
		handle: currentThread,
	}

	return t, nil	
}

func (t *Thread) Close() {
	sys_windows.CloseHandle(t.handle)
}


// Return Thread Token. This function return a nil Token if 
// the call to OpenThreadToken return the error `ERROR_NO_TOKEN`.
func (t *Thread) GetToken() (*tokens.Token, error) {
	var token sys_windows.Token
	if err := sys_windows.OpenThreadToken(t.handle, sys_windows.TOKEN_QUERY, true, &token); err != nil {

		if err == sys_windows.ERROR_NO_TOKEN {
			return nil, nil
		}

		return nil, fmt.Errorf("cannot open thread token: %s", err)
	}

	threadToken := tokens.Token(token)
	return &threadToken, nil
}
