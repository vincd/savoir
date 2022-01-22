package crypto

import (
	"reflect"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/windows"
)

var (
	KiwiBCryptKeyType   = reflect.TypeOf(KiwiBCryptKey{})
	KiwiBCryptKey8Type  = reflect.TypeOf(KiwiBCryptKey8{})
	KiwiBCryptKey81Type = reflect.TypeOf(KiwiBCryptKey81{})
)

var LsaSrvCryptoKeysSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows7,
		Pattern:               []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d},
		Offsets: []int64{
			int64(63),
			int64(-69),
			int64(25),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows7,
		BuildNumberMax:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d},
		Offsets: []int64{
			int64(59),
			int64(-61),
			int64(25),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows8,
		BuildNumberMax:        windows.BuildNumberWindows10_1507,
		Pattern:               []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d},
		Offsets: []int64{
			int64(62),
			int64(-70),
			int64(23),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1507,
		BuildNumberMax:        windows.BuildNumberWindows10_1809,
		Pattern:               []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
		Offsets: []int64{
			int64(61),
			int64(-73),
			int64(16),
		},
	},
	// TODO: BuildNumberWindows10_1809 seems to use the same offsets as previous signature
	/*	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1809,
		BuildNumberMax:        windows.BuildNumberWindows10_1903,
		Pattern:               []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
		Offsets: []int64{
			int64(61),
			int64(-73),
			int64(16),
		},
	},*/
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1809,
		// BuildNumberMin:        windows.BuildNumberWindows10_1903,
		Pattern: []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15},
		Offsets: []int64{
			int64(67),
			int64(-89),
			int64(16),
		},
	},

	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsVista,
		BuildNumberMax:        windows.BuildNumberWindows8,
		Pattern:               []byte{0x6a, 0x02, 0x6a, 0x10, 0x68},
		Offsets: []int64{
			int64(5),
			int64(-76),
			int64(-21),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows8,
		BuildNumberMax:        windows.BuildNumberWindowsBlue,
		Pattern:               []byte{0x6a, 0x02, 0x6a, 0x10, 0x68},
		Offsets: []int64{
			int64(5),
			int64(-69),
			int64(-18),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindowsBlue,
		BuildNumberMax:        windows.BuildNumberWindows10_1507,
		Pattern:               []byte{0x6a, 0x02, 0x6a, 0x10, 0x68},
		Offsets: []int64{
			int64(5),
			int64(-79),
			int64(-22),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows10_1507,
		Pattern:               []byte{0x6a, 0x02, 0x6a, 0x10, 0x68},
		Offsets: []int64{
			int64(5),
			int64(-79),
			int64(-22),
		},
	},
}
