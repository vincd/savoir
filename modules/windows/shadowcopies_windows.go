package windows

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/vincd/savoir/windows/ntdll"
)


func ListShadowCopies() ([]string, error) {
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
					shadowCopies = append(shadowCopies, shadowCopyPath)
				}
			}
		}

		start = context
		restartScan = false
	}

	return shadowCopies, nil
}