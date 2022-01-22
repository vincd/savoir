package windows

type Arch uint16

const (
	ProcessorArchitectureX86     Arch = 0
	ProcessorArchitectureMips    Arch = 1
	ProcessorArchitectureAlpha   Arch = 2
	ProcessorArchitecturePPC     Arch = 3
	ProcessorArchitectureSHX     Arch = 4 // Super-H
	ProcessorArchitectureARM     Arch = 5
	ProcessorArchitectureIA64    Arch = 6
	ProcessorArchitectureAlpha64 Arch = 7
	ProcessorArchitectureMSIL    Arch = 8 // Microsoft Intermediate Language
	ProcessorArchitectureAMD64   Arch = 9
	ProcessorArchitectureWoW64   Arch = 10
	ProcessorArchitectureARM64   Arch = 12
	ProcessorArchitectureUnknown Arch = 0xffff
)

func (a Arch) String() string {
	if a == ProcessorArchitectureAMD64 {
		return "x64"
	} else if a == ProcessorArchitectureX86 {
		return "x86"
	} else if a == ProcessorArchitectureARM64 {
		return "arm"
	} else {
		return "Unknow"
	}
}

func (a Arch) Isx64() bool {
	return a == ProcessorArchitectureAMD64
}

func (a Arch) Isx86() bool {
	return a == ProcessorArchitectureX86
}
