package ssp

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/windows"
)

var sspSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsXP,
		BuildNumberMax:        windows.BuildNumberWindowsVista,
		Pattern:               []byte{0xc7, 0x43, 0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15},
		Offsets: []int64{
			int64(16),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows10_1507,
		Pattern:               []byte{0xc7, 0x47, 0x24, 0x43, 0x72, 0x64, 0x41, 0x48, 0x89, 0x47, 0x78, 0xff, 0x15},
		Offsets: []int64{
			int64(20),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1507,
		BuildNumberMax:        windows.BuildNumberWindows10_2004,
		Pattern:               []byte{0x24, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15},
		Offsets: []int64{
			int64(14),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_2004,
		Pattern:               []byte{0x24, 0x43, 0x72, 0x64, 0x41, 0x48, 0xff, 0x15},
		Offsets: []int64{
			int64(20),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsXP,
		Pattern:               []byte{0x1c, 0x43, 0x72, 0x64, 0x41, 0xff, 0x15},
		Offsets: []int64{
			int64(12),
		},
	},
}
