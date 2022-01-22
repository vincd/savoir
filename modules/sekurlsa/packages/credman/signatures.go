package credman

import (
	"reflect"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

var (
	kiwiCredmanListEntry5Type  = reflect.TypeOf(KiwiCredmanListEntry5{})
	kiwiCredmanListEntry60Type = reflect.TypeOf(KiwiCredmanListEntry60{})
	kiwiCredmanListEntryType   = reflect.TypeOf(KiwiCredmanListEntry{})
)

var credmanSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMax:        windows.BuildNumberWindowsVista,
		Offsets: []int64{
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "User", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "Server2", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "EncPassword", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "EncPasswordLength", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "Flink", true),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows7,
		Offsets: []int64{
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "User", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "Server2", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "EncPassword", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "EncPasswordLength", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "Flink", true),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows7,
		Offsets: []int64{
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "User", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "Server2", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "EncPassword", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "EncPasswordLength", true),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "Flink", true),
		},
	},

	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMax:        windows.BuildNumberWindowsVista,
		Offsets: []int64{
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "User", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "Server2", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "EncPassword", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "EncPasswordLength", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry5Type, "Flink", false),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows7,
		Offsets: []int64{
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "User", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "Server2", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "EncPassword", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "EncPasswordLength", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntry60Type, "Flink", false),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows7,
		Offsets: []int64{
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "User", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "Server2", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "EncPassword", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "EncPasswordLength", false),
			binary.GetStructureFieldOffset(kiwiCredmanListEntryType, "Flink", false),
		},
	},
}
