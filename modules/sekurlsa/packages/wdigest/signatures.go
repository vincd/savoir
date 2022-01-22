package wdigest

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/windows"
)

var wdigestSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsXP,
		BuildNumberMax:        windows.BuildNumberWindows2K3,
		Pattern:               []byte{0x48, 0x3b, 0xda, 0x74},
		Offsets: []int64{
			int64(-4),
			int64(36),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows2K3,
		BuildNumberMax:        windows.BuildNumberWindowsVista,
		Pattern:               []byte{0x48, 0x3b, 0xda, 0x74},
		Offsets: []int64{
			int64(-4),
			int64(48),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		Pattern:               []byte{0x48, 0x3b, 0xd9, 0x74},
		Offsets: []int64{
			int64(-4),
			int64(48),
		},
	},

	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsXP,
		BuildNumberMax:        windows.BuildNumberWindows2K3,
		Pattern:               []byte{0x74, 0x18, 0x8b, 0x4d, 0x08, 0x8b, 0x11},
		Offsets: []int64{
			int64(-6),
			int64(36),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows2K3,
		BuildNumberMax:        windows.BuildNumberWindowsVista,
		Pattern:               []byte{0x74, 0x18, 0x8b, 0x4d, 0x08, 0x8b, 0x11},
		Offsets: []int64{
			int64(-6),
			int64(28),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberMinWindowsBlue,
		Pattern:               []byte{0x74, 0x11, 0x8b, 0x0b, 0x39, 0x4e, 0x10},
		Offsets: []int64{
			int64(-6),
			int64(32),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberMinWindowsBlue,
		BuildNumberMax:        windows.BuildNumberMinWindows10,
		Pattern:               []byte{0x74, 0x15, 0x8b, 0x0a, 0x39, 0x4e, 0x10},
		Offsets: []int64{
			int64(-4),
			int64(32),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberMinWindows10,
		BuildNumberMax:        windows.BuildNumberWindows10_1809,
		Pattern:               []byte{0x74, 0x15, 0x8b, 0x0f, 0x39, 0x4e, 0x10},
		Offsets: []int64{
			int64(-6),
			int64(32),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows10_1809,
		Pattern:               []byte{0x74, 0x15, 0x8b, 0x17, 0x39, 0x56, 0x10},
		Offsets: []int64{
			int64(-6),
			int64(32),
		},
	},
}
