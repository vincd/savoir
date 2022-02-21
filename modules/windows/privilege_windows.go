package windows

import (
	"github.com/vincd/savoir/windows/ntdll"
)


// Ask a privilege (call to `RtlAdjustPrivilege`)
func AskPrivilege(privId ntdll.SePrivilege) error {
	var previousState bool
	if status := ntdll.RtlAdjustPrivilege(uint32(privId), true, false, &previousState); !status.IsSuccess() {
		return status.Error()
	}

	return nil
}

func AskPrivilegeSeDebug() error {
	return AskPrivilege(ntdll.SE_DEBUG)
}
