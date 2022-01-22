//go:build windows
// +build windows

package ntdll

import "unsafe"

var (
	procNtOpenDirectoryObject      = modntdll.NewProc("NtOpenDirectoryObject")
	procNtQueryDirectoryObject     = modntdll.NewProc("NtQueryDirectoryObject")
	procNtOpenSymbolicLinkObject   = modntdll.NewProc("NtOpenSymbolicLinkObject")
	procNtQuerySymbolicLinkObject  = modntdll.NewProc("NtQuerySymbolicLinkObject")
	procNtCreateSymbolicLinkObject = modntdll.NewProc("NtCreateSymbolicLinkObject")
	procNtCreateDirectoryObject    = modntdll.NewProc("NtCreateDirectoryObject")
	procNtQueryObject              = modntdll.NewProc("NtQueryObject")
	procNtDuplicateObject          = modntdll.NewProc("NtDuplicateObject")
)

const (
	OBJ_INHERIT            = 0x00000002
	OBJ_PERMANENT          = 0x00000010
	OBJ_EXCLUSIVE          = 0x00000020
	OBJ_CASE_INSENSITIVE   = 0x00000040
	OBJ_OPENIF             = 0x00000080
	OBJ_OPENLINK           = 0x00000100
	OBJ_KERNEL_HANDLE      = 0x00000200
	OBJ_FORCE_ACCESS_CHECK = 0x00000400
	OBJ_VALID_ATTRIBUTES   = 0x000007F2
)

// typedef DWORD ACCESS_MASK
type AccessMask uint32

// see winnt.h
const (
	DELETE       AccessMask = 0x00010000
	READ_CONTROL            = 0x00020000
	WRITE_DAC               = 0x00040000
	WRITE_OWNER             = 0x00080000
	SYNCHRONIZE             = 0x00100000

	STANDARD_RIGHTS_READ    = 0x00020000
	STANDARD_RIGHTS_WRITE   = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE = READ_CONTROL

	STANDARD_RIGHTS_ALL = 0x001F0000

	SPECIFIC_RIGHTS_ALL    = 0x0000FFFF
	ACCESS_SYSTEM_SECURITY = 0x01000000

	DIRECTORY_QUERY               = 0x00000001
	DIRECTORY_TRAVERSE            = 0x00000002
	DIRECTORY_CREATE_OBJECT       = 0x00000004
	DIRECTORY_CREATE_SUBDIRECTORY = 0x00000008
	DIRECTORY_ALL_ACCESS          = 0x0000000f

	KEY_QUERY_VALUE        = 0x00000001
	KEY_SET_VALUE          = 0x00000002
	KEY_CREATE_SUB_KEY     = 0x00000004
	KEY_ENUMERATE_SUB_KEYS = 0x00000008
	KEY_NOTIFY             = 0x00000010
	KEY_CREATE_LINK        = 0x00000020
	KEY_WOW64_64KEY        = 0x00000100
	KEY_WOW64_32KEY        = 0x00000200
	KEY_WOW64_RES          = 0x00000300

	KEY_READ       = ((STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) &^ SYNCHRONIZE)
	KEY_WRITE      = ((STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY) &^ SYNCHRONIZE)
	KEY_EXECUTE    = ((KEY_READ) &^ SYNCHRONIZE)
	KEY_ALL_ACCESS = ((STANDARD_RIGHTS_ALL | KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_CREATE_LINK) &^ SYNCHRONIZE)
)

// ObjectAttributes has been derived from the OBJECT_ATTRIBUTES struct definition.
type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            Handle
	ObjectName               *UnicodeString
	Attributes               uint32
	SecurityDescriptor       *byte
	SecurityQualityOfService *byte
}

type ObjectInformationClass uint32

const (
	ObjectBasicInformation ObjectInformationClass = 0
	ObjectNameInformation                         = 1
	ObjectTypeInformation                         = 2
	ObjectAllInformation                          = 3
	ObjectDataInformation                         = 4
)

type GenericMapping struct {
	GenericRead    AccessMask
	GenericWrite   AccessMask
	GenericExecute AccessMask
	GenericAll     AccessMask
}

type ObjectTypeInformationT struct {
	TypeName                   UnicodeString
	TotalNumberOfObjects       uint32
	TotalNumberOfHandles       uint32
	TotalPagedPoolUsage        uint32
	TotalNonPagedPoolUsage     uint32
	TotalNamePoolUsage         uint32
	TotalHandleTableUsage      uint32
	HighWaterNumberOfObjects   uint32
	HighWaterNumberOfHandles   uint32
	HighWaterPagedPoolUsage    uint32
	HighWaterNonPagedPoolUsage uint32
	HighWaterNamePoolUsage     uint32
	HighWaterHandleTableUsage  uint32
	InvalidAttributes          uint32
	GenericMapping             GenericMapping
	ValidAccessMask            uint32
	SecurityRequired           bool
	MaintainHandleCount        bool
	TypeIndex                  byte
	ReservedByte               byte
	PoolType                   uint32
	DefaultPagedPoolCharge     uint32
	DefaultNonPagedPoolCharge  uint32
}

type ObjectAllInformationT struct {
	NumberOfObjects       uint64
	ObjectTypeInformation []ObjectTypeInformationT
}

// FIXME: PVOID -> *byte or PVOID -> uintptr?a
func NewObjectAttributes(objectName string, attr uint32, rootdir Handle, sd *byte) (oa *ObjectAttributes) {
	oa = &ObjectAttributes{
		Length:             uint32(unsafe.Sizeof(*oa)),
		RootDirectory:      rootdir,
		ObjectName:         NewUnicodeString(objectName),
		Attributes:         attr,
		SecurityDescriptor: sd,
	}
	return
}

// ObjectDirectoryInformationT has been derived from the OBJECT_DIRECTORY_INFORMATION struct definition.
type ObjectDirectoryInformationT struct {
	Name     UnicodeString
	TypeName UnicodeString
}

func NtOpenDirectoryObject(
	DirectoryHandle *Handle,
	DesiredAccess AccessMask,
	ObjectAttributes *ObjectAttributes,
) NtStatus {
	r0, _, _ := procNtOpenDirectoryObject.Call(uintptr(unsafe.Pointer(DirectoryHandle)),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(ObjectAttributes)))
	return NtStatus(r0)
}

func NtQueryDirectoryObject(
	DirectoryHandle Handle,
	Buffer *byte,
	Length uint32,
	ReturnSingleEntry bool,
	RestartScan bool,
	Context *uint32,
	ReturnLength *uint32,
) NtStatus {
	r0, _, _ := procNtQueryDirectoryObject.Call(uintptr(DirectoryHandle),
		uintptr(unsafe.Pointer(Buffer)),
		uintptr(Length),
		fromBool(ReturnSingleEntry),
		fromBool(RestartScan),
		uintptr(unsafe.Pointer(Context)),
		uintptr(unsafe.Pointer(ReturnLength)))
	return NtStatus(r0)
}

func NtOpenSymbolicLinkObject(
	LinkHandle *Handle,
	DesiredAccess AccessMask,
	ObjectAttributes *ObjectAttributes,
) NtStatus {
	r0, _, _ := procNtOpenSymbolicLinkObject.Call(uintptr(unsafe.Pointer(LinkHandle)),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(ObjectAttributes)))
	return NtStatus(r0)
}

func NtQuerySymbolicLinkObject(
	LinkHandle Handle,
	LinkTarget *UnicodeString,
	ReturnedLength *uint32,
) NtStatus {
	r0, _, _ := procNtQuerySymbolicLinkObject.Call(uintptr(LinkHandle),
		uintptr(unsafe.Pointer(LinkTarget)),
		uintptr(unsafe.Pointer(ReturnedLength)))
	return NtStatus(r0)
}

func NtCreateSymbolicLinkObject(
	SymbolicLinkHandle *Handle,
	DesiredAccess AccessMask,
	ObjectAttributes *ObjectAttributes,
	TargetName *UnicodeString,
) NtStatus {
	r0, _, _ := procNtCreateSymbolicLinkObject.Call(uintptr(unsafe.Pointer(SymbolicLinkHandle)),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(ObjectAttributes)),
		uintptr(unsafe.Pointer(TargetName)))
	return NtStatus(r0)
}

func NtCreateDirectoryObject(
	DirectoryHandle *Handle,
	DesiredAccess AccessMask,
	ObjectAttributes *ObjectAttributes,
) NtStatus {
	r0, _, _ := procNtCreateDirectoryObject.Call(uintptr(unsafe.Pointer(DirectoryHandle)),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(ObjectAttributes)))
	return NtStatus(r0)
}

func NtQueryObject(
	Handle Handle,
	ObjectInformationClass ObjectInformationClass,
	ObjectInformation *byte,
	ObjectInformationLength uint32,
	ReturnLength *uint32,
) NtStatus {
	r0, _, _ := procNtQueryObject.Call(uintptr(Handle),
		uintptr(ObjectInformationClass),
		uintptr(unsafe.Pointer(ObjectInformation)),
		uintptr(ObjectInformationLength),
		uintptr(unsafe.Pointer(ReturnLength)))
	return NtStatus(r0)
}

func QueryObject(handle Handle, objectInformationClass ObjectInformationClass) (*ObjectTypeInformationT, NtStatus) {
	var returnLength uint32
	buf := make([]byte, 0x100)

	status := NtQueryObject(handle, objectInformationClass, &buf[0], uint32(len(buf)), &returnLength)
	for !status.IsSuccess() {
		buf = make([]byte, returnLength)
		status = NtQueryObject(handle, objectInformationClass, &buf[0], uint32(len(buf)), &returnLength)

		if status.IsSuccess() {
			break
		} else if status == STATUS_INFO_LENGTH_MISMATCH {
			continue
		} else if status.IsError() {
			return nil, status
		}
	}

	objInfo := (*ObjectTypeInformationT)(unsafe.Pointer(&buf[0]))

	return objInfo, STATUS_SUCCESS
}

func NtDuplicateObject(
	SourceProcessHandle Handle,
	SourceHandle Handle,
	TargetProcessHandle Handle,
	TargetHandle *Handle,
	DesiredAccess AccessMask,
	HandleAttributes uint32,
	Options uint32,
) NtStatus {
	r0, _, _ := procNtDuplicateObject.Call(uintptr(SourceProcessHandle),
		uintptr(SourceHandle),
		uintptr(TargetProcessHandle),
		uintptr(unsafe.Pointer(TargetHandle)),
		uintptr(DesiredAccess),
		uintptr(HandleAttributes),
		uintptr(Options))
	return NtStatus(r0)
}
