//go:build windows
// +build windows

package ntdll

import (
	"unsafe"
)

type SystemInformationClass uint32

const (
	SystemInformationBasicInformation                SystemInformationClass = 0
	SystemInformationProcessorInformation                                   = 1
	SystemInformationPerformanceInformation                                 = 2
	SystemInformationTimeOfDayInformation                                   = 3
	SystemInformationPathInformation                                        = 4
	SystemInformationProcessInformation                                     = 5
	SystemInformationCallCountInformation                                   = 6
	SystemInformationDeviceInformation                                      = 7
	SystemInformationProcessorPerformanceInformation                        = 8
	SystemInformationFlagsInformation                                       = 9
	SystemInformationCallTimeInformation                                    = 10
	SystemInformationModuleInformation                                      = 11
	SystemInformationLocksInformation                                       = 12
	SystemInformationStackTraceInformation                                  = 13
	SystemInformationPagedPoolInformation                                   = 14
	SystemInformationNonPagedPoolInformation                                = 15
	SystemInformationHandleInformation                                      = 16
	SystemInformationObjectInformation                                      = 17
	SystemInformationPageFileInformation                                    = 18
	SystemInformationVdmInstemulInformation                                 = 19
	SystemInformationVdmBopInformation                                      = 20
	SystemInformationFileCacheInformation                                   = 21
	SystemInformationPoolTagInformation                                     = 22
	SystemInformationInterruptInformation                                   = 23
	SystemInformationDpcBehaviorInformation                                 = 24
	SystemInformationFullMemoryInformation                                  = 25
	SystemInformationLoadGdiDriverInformation                               = 26
	SystemInformationUnloadGdiDriverInformation                             = 27
	SystemInformationTimeAdjustmentInformation                              = 28
	SystemInformationSummaryMemoryInformation                               = 29
	SystemInformationNextEventIdInformation                                 = 30
	SystemInformationEventIdsInformation                                    = 31
	SystemInformationCrashDumpInformation                                   = 32
	SystemInformationExceptionInformation                                   = 33
	SystemInformationCrashDumpStateInformation                              = 34
	SystemInformationKernelDebuggerInformation                              = 35
	SystemInformationContextSwitchInformation                               = 36
	SystemInformationRegistryQuotaInformation                               = 37
	SystemInformationExtendServiceTableInformation                          = 38
	SystemInformationPrioritySeperation                                     = 39
	SystemInformationPlugPlayBusInformation                                 = 40
	SystemInformationDockInformation                                        = 41
	SystemInformationPowerInformation                                       = 42
	SystemInformationProcessorSpeedInformation                              = 43
	SystemInformationCurrentTimeZoneInformation                             = 44
	SystemInformationLookasideInformation                                   = 45
)

var (
	procNtQuerySystemInformation = modntdll.NewProc("NtQuerySystemInformation")
)

func NtQuerySystemInformation(SystemInformationClass SystemInformationClass, SystemInformation *byte, SystemInformationLength uint32, ReturnLength *uint32) NtStatus {
	r0, _, _ := procNtQuerySystemInformation.Call(
		uintptr(SystemInformationClass),
		uintptr(unsafe.Pointer(SystemInformation)),
		uintptr(SystemInformationLength),
		uintptr(unsafe.Pointer(ReturnLength)))

	return NtStatus(r0)
}

/*// Helper function to call NtQuerySystemInformation
func QuerySystemInformation(systemInformationClass SystemInformationClass) ([]byte, NtStatus) {
	var returnLength uint32
	buf := make([]byte, 0x100)

	status := NtQuerySystemInformation(systemInformationClass, &buf[0], uint32(len(buf)), &returnLength)
	for !status.IsSuccess() {
		buf = make([]byte, returnLength)
		status = NtQuerySystemInformation(systemInformationClass, &buf[0], uint32(len(buf)), &returnLength)

		if status.IsSuccess() {
			break
		} else if status == STATUS_INFO_LENGTH_MISMATCH {
			continue
		} else if status.IsError() {
			return nil, status
		}
	}

	return buf[0:returnLength], STATUS_SUCCESS
}*/

type kPriority int32

type SystemProcessInformation struct {
	NextEntryOffset              uint32        // ULONG
	NumberOfThreads              uint32        // ULONG
	WorkingSetPrivateSize        int64         // LARGE_INTEGER
	HardFaultCount               uint32        // ULONG
	NumberOfThreadsHighWatermark uint32        // ULONG
	CycleTime                    uint64        // ULONGLONG
	CreateTime                   int64         // LARGE_INTEGER
	UserTime                     int64         // LARGE_INTEGER
	KernelTime                   int64         // LARGE_INTEGER
	ImageName                    UnicodeString // UNICODE_STRING
	BasePriority                 kPriority     // KPRIORITY
	UniqueProcessID              uintptr       // HANDLE
	InheritedFromUniqueProcessID uintptr       // HANDLE
	HandleCount                  uint32        // ULONG
	SessionID                    uint32        // ULONG
	UniqueProcessKey             *uint32       // ULONG_PTR
	PeakVirtualSize              uintptr       // SIZE_T
	VirtualSize                  uintptr       // SIZE_T
	PageFaultCount               uint32        // ULONG
	PeakWorkingSetSize           uintptr       // SIZE_T
	WorkingSetSize               uintptr       // SIZE_T
	QuotaPeakPagedPoolUsage      uintptr       // SIZE_T
	QuotaPagedPoolUsage          uintptr       // SIZE_T
	QuotaPeakNonPagedPoolUsage   uintptr       // SIZE_T
	QuotaNonPagedPoolUsage       uintptr       // SIZE_T
	PagefileUsage                uintptr       // SIZE_T
	PeakPagefileUsage            uintptr       // SIZE_T
	PrivatePageCount             uintptr       // SIZE_T
	ReadOperationCount           int64         // LARGE_INTEGER
	WriteOperationCount          int64         // LARGE_INTEGER
	OtherOperationCount          int64         // LARGE_INTEGER
	ReadTransferCount            int64         // LARGE_INTEGER
	WriteTransferCount           int64         // LARGE_INTEGER
	OtherTransferCount           int64         // LARGE_INTEGER
}

type SystemHandle struct {
	UniqueProcessID  uint32
	ObjectTypeIndex  uint8
	HandleAttributes uint8
	HandleValue      uint16
	Object           uint64
	GrantedAccess    uint32
}

type SystemHandleInformation struct {
	HandlesCount uint64
	Handles      []SystemHandle
}

/*func QuerySystemProcessInformation() ([]SystemProcessInformation, error) {
	buf, status := QuerySystemInformation(systemProcessInformation)
	if !status.IsSuccess() {
		return nil, status.Error()
	}

	processInfos := make([]SystemProcessInformation, 0)
	currentOffset := uint32(0)

	processInfo := (*SystemProcessInformation)(unsafe.Pointer(&buf[currentOffset]))
	processInfos = append(processInfos, *processInfo)

	for processInfo.NextEntryOffset > 0 {
		currentOffset += processInfo.NextEntryOffset
		processInfo = (*SystemProcessInformation)(unsafe.Pointer(&buf[currentOffset]))
		processInfos = append(processInfos, *processInfo)
	}

	return processInfos, nil
}

func QuerySystemHandleInformation() (*SystemHandleInformation, error) {
	// TODO: check x64 or x86
	buf, status := QuerySystemInformation(systemHandleInformation)
	if !status.IsSuccess() {
		return nil, status.Error()
	}

	sysinfo := (*SystemHandleInformation)(unsafe.Pointer(&buf[0]))
	handles := make([]SystemHandle, int(sysinfo.HandlesCount))
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&handles))
	hdr.Data = uintptr(unsafe.Pointer(&buf[8]))
	sysinfo.Handles = handles

	return sysinfo, nil
}
*/
