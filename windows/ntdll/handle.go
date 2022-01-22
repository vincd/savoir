//go:build windows
// +build windows

package ntdll

var (
	procNtClose = modntdll.NewProc("NtClose")
)

func NtClose(
	Handle Handle,
) NtStatus {
	r0, _, _ := procNtClose.Call(uintptr(Handle))
	return NtStatus(r0)
}
