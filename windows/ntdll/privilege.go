//go:build windows
// +build windows

package ntdll

import "unsafe"

var (
	procRtlAdjustPrivilege = modntdll.NewProc("RtlAdjustPrivilege")
)

type SePrivilege uint32

const (
	SE_CREATE_TOKEN           = SePrivilege(2)
	SE_ASSIGNPRIMARYTOKE      = SePrivilege(3)
	SE_LOCK_MEMORY            = SePrivilege(4)
	SE_INCREASE_QUOTA         = SePrivilege(5)
	SE_UNSOLICITED_INPUT      = SePrivilege(6)
	SE_TCB                    = SePrivilege(7)
	SE_SECURITY               = SePrivilege(8)
	SE_TAKE_OWNERSHIP         = SePrivilege(9)
	SE_LOAD_DRIVER            = SePrivilege(10)
	SE_SYSTEM_PROFILE         = SePrivilege(11)
	SE_SYSTEMTIME             = SePrivilege(12)
	SE_PROF_SINGLE_PROCESS    = SePrivilege(13)
	SE_INC_BASE_PRIORITY      = SePrivilege(14)
	SE_CREATE_PAGEFILE        = SePrivilege(15)
	SE_CREATE_PERMANENT       = SePrivilege(16)
	SE_BACKU                  = SePrivilege(17)
	SE_RESTORE                = SePrivilege(18)
	SE_SHUTDOWN               = SePrivilege(19)
	SE_DEBUG                  = SePrivilege(20)
	SE_AUDIT                  = SePrivilege(21)
	SE_SYSTEM_ENVIRONMENT     = SePrivilege(22)
	SE_CHANGE_NOTIFY          = SePrivilege(23)
	SE_REMOTE_SHUTDOWN        = SePrivilege(24)
	SE_UNDOCK                 = SePrivilege(25)
	SE_SYNC_AGENT             = SePrivilege(26)
	SE_ENABLE_DELEGATION      = SePrivilege(27)
	SE_MANAGE_VOLUME          = SePrivilege(28)
	SE_IMPERSONATE            = SePrivilege(29)
	SE_CREATE_GLOBAL          = SePrivilege(30)
	SE_TRUSTED_CREDMAN_ACCESS = SePrivilege(31)
	SE_RELABEL                = SePrivilege(32)
	SE_INC_WORKING_SET        = SePrivilege(33)
	SE_TIME_ZONE              = SePrivilege(34)
	SE_CREATE_SYMBOLIC_LINK   = SePrivilege(35)
)

func RtlAdjustPrivilege(Privilege uint32, Enable bool, CurrentThread bool, pPreviousState *bool) NtStatus {
	r0, _, _ := procRtlAdjustPrivilege.Call(
		uintptr(Privilege),
		fromBool(Enable),
		fromBool(CurrentThread),
		uintptr(unsafe.Pointer(pPreviousState)),
	)
	return NtStatus(r0)
}
