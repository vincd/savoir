package cloudap

import (
	// "reflect"
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/windows"
)

// var KiwiMasterKeyCacheEntryType = reflect.TypeOf(KiwiMasterKeyCacheEntry{})

var cloudapSignatures = []globals.Signature{
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureAMD64,
		BuildNumberMin:        windows.BuildNumberWindows10_1909,
		Pattern:               []byte{0x44, 0x8b, 0x01, 0x44, 0x39, 0x42, 0x18, 0x75},
		Offsets: []int64{
			int64(-9),
		},
	},
	globals.Signature{
		ProcessorArchitecture: windows.ProcessorArchitectureX86,
		BuildNumberMin:        windows.BuildNumberWindows10_1909,
		Pattern:               []byte{0x8b, 0x31, 0x39, 0x72, 0x10, 0x75},
		Offsets: []int64{
			int64(-8),
		},
	},
}
