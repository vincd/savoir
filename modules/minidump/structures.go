package minidump

import (
	"github.com/vincd/savoir/windows"
)

type StreamType uint32

const (
	UnusedStream              StreamType = 0
	ReservedStream0           StreamType = 1
	ReservedStream1           StreamType = 2
	ThreadListStream          StreamType = 3
	ModuleListStream          StreamType = 4
	MemoryListStream          StreamType = 5
	ExceptionStream           StreamType = 6
	SystemInfoStream          StreamType = 7
	ThreadExListStream        StreamType = 8
	Memory64ListStream        StreamType = 9
	CommentStreamA            StreamType = 10
	CommentStreamW            StreamType = 11
	HandleDataStream          StreamType = 12
	FunctionTableStream       StreamType = 13
	UnloadedModuleStream      StreamType = 14
	MiscInfoStream            StreamType = 15
	MemoryInfoListStream      StreamType = 16
	ThreadInfoListStream      StreamType = 17
	HandleOperationListStream StreamType = 18
	TokenStream               StreamType = 19
	JavascriptDataStream      StreamType = 20
	SystemMemoryInfoStream    StreamType = 21
	ProcessVMCounterStream    StreamType = 22
)

type MinidumpHeader struct {
	Signature          [4]byte
	Version            uint32
	NumberOfStreams    uint32
	StreamDirectoryRva uint32
	CheckSum           uint32
	Reserved           uint32
	TimeDateStamp      uint32
	Flags              uint64
}

type LocationDescriptor struct {
	DataSize uint32
	Rva      uint32
}

type Directory struct {
	StreamType StreamType
	Location   LocationDescriptor
}

type SystemInfo struct {
	ProcessorArchitecture windows.Arch        `json:"architecture"`
	ProcessorLevel        uint16              `json:"-"`
	ProcessorRevision     uint16              `json:"-"`
	NumberOfProcessors    byte                `json:"-"`
	ProductType           byte                `json:"-"`
	MajorVersion          uint32              `json:"major_version"`
	MinorVersion          uint32              `json:"minor_version"`
	BuildNumber           windows.BuildNumber `json:"build_number"`
	PlatformId            uint32              `json:"-"`
	CSDVersionRva         uint32              `json:"-"`
	SuiteMask             uint16              `json:"-"`
	Reserved2             uint16              `json:"-"`
	// CPU_INFORMATION Cpu;
}

type VSFixedFileInfo struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

type Module struct {
	BaseOfImage   uint64
	SizeOfImage   uint32
	CheckSum      uint32
	TimeDateStamp uint32
	ModuleNameRva uint32
	VersionInfo   VSFixedFileInfo
	CvRecord      LocationDescriptor
	MiscRecord    LocationDescriptor
	Reserved0     uint64
	Reserved1     uint64
}

type ModuleList struct {
	NumberOfModules uint32
	Modules         []Module
}

type MemoryDescriptor64 struct {
	StartOfMemoryRange uint64
	DataSize           uint64
}

type Memory64List struct {
	NumberOfMemoryRanges uint64
	BaseRva              uint64
	MemoryRanges         []MemoryDescriptor64
}
