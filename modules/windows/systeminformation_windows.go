package windows

import (
	"reflect"
	"unsafe"

	"github.com/vincd/savoir/windows/ntdll"
)


// Helper function to call NtQuerySystemInformation
func QuerySystemInformation(systemInformationClass ntdll.SystemInformationClass) ([]byte, ntdll.NtStatus) {
	var returnLength uint32
	buf := make([]byte, 0x100)

	status := ntdll.NtQuerySystemInformation(systemInformationClass, &buf[0], uint32(len(buf)), &returnLength)
	for !status.IsSuccess() {
		buf = make([]byte, returnLength)
		status = ntdll.NtQuerySystemInformation(systemInformationClass, &buf[0], uint32(len(buf)), &returnLength)

		if status.IsSuccess() {
			break
		} else if status == ntdll.STATUS_INFO_LENGTH_MISMATCH {
			continue
		} else if status.IsError() {
			return nil, status
		}
	}

	return buf[0:returnLength], ntdll.STATUS_SUCCESS
}

func QuerySystemProcessInformation() ([]ntdll.SystemProcessInformation, error) {
	buf, status := QuerySystemInformation(ntdll.SystemInformationProcessInformation)
	if !status.IsSuccess() {
		return nil, status.Error()
	}

	processInfos := make([]ntdll.SystemProcessInformation, 0)
	currentOffset := uint32(0)

	processInfo := (*ntdll.SystemProcessInformation)(unsafe.Pointer(&buf[currentOffset]))
	processInfos = append(processInfos, *processInfo)

	for processInfo.NextEntryOffset > 0 {
		currentOffset += processInfo.NextEntryOffset
		processInfo = (*ntdll.SystemProcessInformation)(unsafe.Pointer(&buf[currentOffset]))
		processInfos = append(processInfos, *processInfo)
	}

	return processInfos, nil
}

func QuerySystemHandleInformation() (*ntdll.SystemHandleInformation, error) {
	// TODO: check x64 or x86
	buf, status := QuerySystemInformation(ntdll.SystemInformationHandleInformation)
	if !status.IsSuccess() {
		return nil, status.Error()
	}

	sysinfo := (*ntdll.SystemHandleInformation)(unsafe.Pointer(&buf[0]))
	handles := make([]ntdll.SystemHandle, int(sysinfo.HandlesCount))
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&handles))
	hdr.Data = uintptr(unsafe.Pointer(&buf[8]))
	sysinfo.Handles = handles

	return sysinfo, nil
}
