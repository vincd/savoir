package globals

import (
	"fmt"
	// "bytes"
	encodingBinary "encoding/binary"

	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

type Signature struct {
	ProcessorArchitecture windows.Arch
	BuildNumber           windows.BuildNumber
	BuildNumberMin        windows.BuildNumber
	BuildNumberMax        windows.BuildNumber
	Pattern               []byte
	Offsets               []int64
}

// Find a signature pattern based on the minidump SystemInfo Architecture and
// BuildNumber.
// Returns the reference within (included) the maximum and minium BuildNumber
func FindSignatureNew(references []Signature, arch windows.Arch, buildNumber windows.BuildNumber) (*Signature, int, error) {
	for i, ref := range references {
		if ref.ProcessorArchitecture == arch {
			if ref.BuildNumberMin > 0 || ref.BuildNumberMax > 0 {
				if ref.BuildNumberMin == 0 {
					if buildNumber < ref.BuildNumberMax {
						return &ref, i, nil
					}
				} else if ref.BuildNumberMax == 0 {
					if ref.BuildNumberMin <= buildNumber {
						return &ref, i, nil
					}
				} else {
					if ref.BuildNumberMin <= buildNumber && buildNumber < ref.BuildNumberMax {
						return &ref, i, nil
					}
				}
			} else {
				return nil, 0, fmt.Errorf("The reference build numbers are incorrects.")
			}
		}
	}

	return nil, 0, fmt.Errorf("Cannot find a signature for build number: %d (%x)", uint32(buildNumber), references[0].Pattern)
}

func FindSignature(references []Signature, arch windows.Arch, buildNumber windows.BuildNumber) (*Signature, error) {
	reference, _, err := FindSignatureNew(references, arch, buildNumber)
	return reference, err
}

func FindSignatureInModuleMemory(m utils.MemoryReader, moduleName string, pattern []byte) (binary.Pointer, error) {
	return m.SearchPatternInModule(moduleName, pattern)
}

func FindStructurePointerFromSignature(m utils.MemoryReader, dllname string, references []Signature) (*binary.Pointer, *Signature, error) {
	reference, err := FindSignature(references, m.ProcessorArchitecture(), m.BuildNumber())
	if err != nil {
		return nil, nil, err
	}

	position, err := FindSignatureInModuleMemory(m, dllname, reference.Pattern)
	if err != nil {
		return nil, nil, err
	}

	buff, err := m.ReadFromPointer(position.WithOffset(reference.Offsets[0]), 8)
	if err != nil {
		return nil, nil, err
	}
	ptrValue := encodingBinary.LittleEndian.Uint64(buff)
	ptr := binary.Pointer(ptrValue)

	if !m.ProcessorArchitecture().Isx64() {
		ptr = binary.Pointer(ptrValue & 0xFFFFFFFF)
	}

	return &ptr, reference, nil
}

func FindStructureFromSignature(m utils.MemoryReader, dllname string, references []Signature, data interface{}) (*Signature, error) {
	ptr, reference, err := FindStructurePointerFromSignature(m, dllname, references)
	if err != nil {
		return nil, err
	}

	if err := m.ReadStructure(*ptr, data); err != nil {
		return nil, err
	}

	return reference, nil
}
