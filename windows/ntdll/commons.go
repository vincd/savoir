//go:build windows
// +build windows

package ntdll

func AskPrivilege(privId SePrivilege) error {
	var previousState bool
	status := RtlAdjustPrivilege(uint32(privId), true, false, &previousState)
	if !status.IsSuccess() {
		return status.Error()
	}

	return nil
}
