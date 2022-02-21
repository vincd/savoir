//go:build windows
// +build windows

package offlinelsa

// From: https://github.com/gtworek/PSBits/blob/master/OfflineSAM/OfflineAddAdmin.c

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/ntdll"
	"github.com/vincd/savoir/windows/ntsecapi"
)

var (
	modOfflineLsa = windows.NewLazySystemDLL("offlinelsa.dll")
)

var (
	procLsaOfflineOpenPolicy             = modOfflineLsa.NewProc("LsaOfflineOpenPolicy")
	procLsaOfflineClose                  = modOfflineLsa.NewProc("LsaOfflineClose")
	procLsaOfflineEnumerateAccounts      = modOfflineLsa.NewProc("LsaOfflineEnumerateAccounts")
	procLsaOfflineFreeMemory             = modOfflineLsa.NewProc("LsaOfflineFreeMemory")
	procLsaOfflineEnumerateAccountRights = modOfflineLsa.NewProc("LsaOfflineEnumerateAccountRights")
	procLsaOfflineAddAccountRights       = modOfflineLsa.NewProc("LsaOfflineAddAccountRights")
)

type OfflineLsaHandle uintptr

type LsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func OpenPolicy(WindowsDirectory string, PolicyHandle *OfflineLsaHandle) error {
	pszWindowsDirectory, err := syscall.UTF16PtrFromString(WindowsDirectory)
	if err != nil {
		return err
	}

	r0, _, err := procLsaOfflineOpenPolicy.Call(
		uintptr(unsafe.Pointer(pszWindowsDirectory)),
		uintptr(unsafe.Pointer(PolicyHandle)),
	)

	if r0 != 0 {
		if err.(windows.Errno) == 0 {
			return ntdll.NtStatus(r0).Error()
		} else {
			return err
		}
	}

	return nil
}

func Close(PolicyHandle OfflineLsaHandle) error {
	r0, _, _ := procLsaOfflineClose.Call(uintptr(PolicyHandle))
	return ntdll.NtStatus(r0).Error()
}

func EnumerateAccounts(PolicyHandle OfflineLsaHandle, EnumerationContext *ntsecapi.LsaEnumerationHandle, Buffer *[]ntsecapi.LsaEnumerationInformation, PreferredMaximumLength uint64, CountReturned *uint64) error {
	r0, _, err := procLsaOfflineEnumerateAccounts.Call(
		uintptr(PolicyHandle),
		uintptr(unsafe.Pointer(EnumerationContext)),
		uintptr(unsafe.Pointer(Buffer)),
		uintptr(PreferredMaximumLength),
		uintptr(unsafe.Pointer(CountReturned)),
	)

	if r0 != 0 {
		if err.(windows.Errno) == 0 {
			return ntdll.NtStatus(r0).Error()
		} else {
			return err
		}
	}

	return nil
}

func FreeMemory(Buffer *byte) error {
	r0, _, _ := procLsaOfflineFreeMemory.Call(uintptr(unsafe.Pointer(Buffer)))
	return ntdll.NtStatus(r0).Error()
}

func EnumerateAccountRights(PolicyHandle OfflineLsaHandle, AccountSid *windows.SID, UserRights *[]LsaUnicodeString, CountOfRights *uint64) error {
	r0, _, err := procLsaOfflineEnumerateAccountRights.Call(
		uintptr(PolicyHandle),
		uintptr(unsafe.Pointer(AccountSid)),
		uintptr(unsafe.Pointer(UserRights)),
		uintptr(unsafe.Pointer(CountOfRights)),
	)

	if r0 != 0 {
		if err.(windows.Errno) == 0 {
			return ntdll.NtStatus(r0).Error()
		} else {
			return err
		}
	}

	return nil
}

func AddAccountRights(PolicyHandle OfflineLsaHandle, AccountSid *windows.SID, UserRights *LsaUnicodeString, CountOfRights uint64) error {
	r0, _, err := procLsaOfflineAddAccountRights.Call(
		uintptr(PolicyHandle),
		uintptr(unsafe.Pointer(AccountSid)),
		uintptr(unsafe.Pointer(UserRights)),
		uintptr(CountOfRights),
	)

	if r0 != 0 {
		if err.(windows.Errno) == 0 {
			return ntdll.NtStatus(r0).Error()
		} else {
			return err
		}
	}

	return nil
}
