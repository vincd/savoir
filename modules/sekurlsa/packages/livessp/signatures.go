package livessp

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/windows"
)

var livesspSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x74, 0x25, 0x8b},
		Offsets: []int64{
			int64(-7),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x8b, 0x16, 0x39, 0x51, 0x24, 0x75, 0x08},
		Offsets: []int64{
			int64(-8),
		},
	},
}
