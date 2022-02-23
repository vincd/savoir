package windows

import (
	"unsafe"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/ntdll"
)

func QueryObject(handle sys_windows.Handle, objectInformationClass ntdll.ObjectInformationClass) ([]byte, ntdll.NtStatus) {
	var returnLength uint32
	buf := make([]byte, 0x100)

	status := ntdll.NtQueryObject(ntdll.Handle(handle), objectInformationClass, &buf[0], uint32(len(buf)), &returnLength)
	for !status.IsSuccess() {
		buf = make([]byte, returnLength)
		status = ntdll.NtQueryObject(ntdll.Handle(handle), objectInformationClass, &buf[0], uint32(len(buf)), &returnLength)

		if status.IsSuccess() {
			break
		} else if status == ntdll.STATUS_INFO_LENGTH_MISMATCH {
			continue
		} else if status.IsError() {
			return nil, status
		}
	}

	return buf, ntdll.STATUS_SUCCESS
}

func QueryObjectBasicInformation(handle sys_windows.Handle) (*ntdll.ObjectBasicInformationT, ntdll.NtStatus) {
	buf, status := QueryObject(handle, ntdll.ObjectBasicInformation)
	if status != ntdll.STATUS_SUCCESS {
		return nil, status
	}

	objInfo := (*ntdll.ObjectBasicInformationT)(unsafe.Pointer(&buf[0]))
	return objInfo, ntdll.STATUS_SUCCESS
}

func QueryObjectTypeInformation(handle sys_windows.Handle) (*ntdll.ObjectTypeInformationT, ntdll.NtStatus) {
	buf, status := QueryObject(handle, ntdll.ObjectTypeInformation)
	if status != ntdll.STATUS_SUCCESS {
		return nil, status
	}

	objInfo := (*ntdll.ObjectTypeInformationT)(unsafe.Pointer(&buf[0]))
	return objInfo, ntdll.STATUS_SUCCESS
}

func DuplicateObject(SourceProcessHandle sys_windows.Handle, SourceHandle sys_windows.Handle, TargetProcessHandle sys_windows.Handle, TargetHandle *sys_windows.Handle, DesiredAccess ntdll.AccessMask, HandleAttributes uint32, Options uint32) ntdll.NtStatus {
	return ntdll.NtDuplicateObject(
		ntdll.Handle(SourceProcessHandle),
		ntdll.Handle(SourceHandle),
		ntdll.Handle(TargetProcessHandle),
		(*ntdll.Handle)(TargetHandle),
		DesiredAccess,
		HandleAttributes,
		Options)
}
