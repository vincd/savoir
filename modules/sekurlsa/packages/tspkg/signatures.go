package tspkg

import (
	"reflect"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

var (
	kiwiTsCredentialType     = reflect.TypeOf(KiwiTsCredential{})
	kiwiTsCredential1607Type = reflect.TypeOf(KiwiTsCredential1607{})
)

var tspkgSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows10_1607,
		Pattern:               []byte{0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d},
		Offsets: []int64{
			int64(7),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "LocallyUniqueIdentifier", true),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "TsPrimary", true),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1607,
		Pattern:               []byte{0x48, 0x83, 0xec, 0x20, 0x48, 0x8d, 0x0d},
		Offsets: []int64{
			int64(7),
			binary.GetStructureFieldOffset(kiwiTsCredential1607Type, "LocallyUniqueIdentifier", true),
			binary.GetStructureFieldOffset(kiwiTsCredential1607Type, "TsPrimary", true),
		},
	},

	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsXP,
		BuildNumberMax:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51, 0x56, 0xbe},
		Offsets: []int64{
			int64(8),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "LocallyUniqueIdentifier", false),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "TsPrimary", false),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows8,
		BuildNumberMax:        windows.BuildNumberWindowsBlue,
		Pattern:               []byte{0x8b, 0xff, 0x53, 0xbb},
		Offsets: []int64{
			int64(4),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "LocallyUniqueIdentifier", false),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "TsPrimary", false),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsBlue,
		BuildNumberMax:        windows.BuildNumberWindows10_1607,
		Pattern:               []byte{0x8b, 0xff, 0x57, 0xbf},
		Offsets: []int64{
			int64(4),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "LocallyUniqueIdentifier", false),
			binary.GetStructureFieldOffset(kiwiTsCredentialType, "TsPrimary", false),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows10_1607,
		Pattern:               []byte{0x8b, 0xff, 0x57, 0xbf},
		Offsets: []int64{
			int64(4),
			binary.GetStructureFieldOffset(kiwiTsCredential1607Type, "LocallyUniqueIdentifier", false),
			binary.GetStructureFieldOffset(kiwiTsCredential1607Type, "TsPrimary", false),
		},
	},
}
