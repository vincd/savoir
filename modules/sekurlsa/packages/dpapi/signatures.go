package dpapi

import (
	"reflect"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/windows"
)

var KiwiMasterKeyCacheEntryType = reflect.TypeOf(KiwiMasterKeyCacheEntry{})

var dapApiSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows2K3,
		BuildNumberMax:        windows.BuildNumberWindowsVista,
		Pattern:               []byte{0x4d, 0x3b, 0xee, 0x49, 0x8b, 0xfd, 0x0f, 0x85},
		Offsets: []int64{
			int64(-4),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows7,
		Pattern:               []byte{0x49, 0x3b, 0xef, 0x48, 0x8b, 0xfd, 0x0f, 0x84},
		Offsets: []int64{
			int64(-4),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows7,
		BuildNumberMax:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x33, 0xc0, 0xeb, 0x20, 0x48, 0x8d, 0x05},
		Offsets: []int64{
			int64(7),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows8,
		BuildNumberMax:        windows.BuildNumberWindowsBlue,
		Pattern:               []byte{0x4c, 0x89, 0x1f, 0x48, 0x89, 0x47, 0x08, 0x49, 0x39, 0x43, 0x08, 0x0f, 0x85},
		Offsets: []int64{
			int64(-4),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsBlue,
		BuildNumberMax:        windows.BuildNumberWindows10_1507,
		Pattern:               []byte{0x08, 0x48, 0x39, 0x48, 0x08, 0x0f, 0x85},
		Offsets: []int64{
			int64(-10),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1507,
		BuildNumberMax:        windows.BuildNumberWindows10_1607,
		Pattern:               []byte{0x48, 0x89, 0x4e, 0x08, 0x48, 0x39, 0x48, 0x08},
		Offsets: []int64{
			int64(-7),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1607,
		Pattern:               []byte{0x48, 0x89, 0x4f, 0x08, 0x48, 0x89, 0x78, 0x08},
		Offsets: []int64{
			int64(11),
		},
	},

	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsXP,
		BuildNumberMax:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x33, 0xc0, 0x40, 0xa3},
		Offsets: []int64{
			int64(-4),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows8,
		BuildNumberMax:        windows.BuildNumberWindowsBlue,
		Pattern:               []byte{0x8b, 0xf0, 0x81, 0xfe, 0xcc, 0x06, 0x00, 0x00, 0x0f, 0x84},
		Offsets: []int64{
			int64(-16),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsBlue,
		Pattern:               []byte{0x33, 0xc0, 0x40, 0xa3},
		Offsets: []int64{
			int64(-4),
		},
	},
}
