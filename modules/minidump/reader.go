package minidump

import (
	"bytes"
	"fmt"
	"time"

	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

func (m Minidump) Read(ptr binary.Pointer, size uint32) ([]byte, error) {
	start := ptr.ToUint64()

	minidumpOffset := uint64(0)
	for _, memory64 := range m.Memory.MemoryRanges {
		// fmt.Printf("readVirtualMemory(%x, %d) %x -> %x\n", ptr, size, memory64.StartOfMemoryRange, memory64.StartOfMemoryRange+memory64.DataSize)
		if memory64.StartOfMemoryRange <= start && start < memory64.StartOfMemoryRange+memory64.DataSize {
			offset := start - memory64.StartOfMemoryRange + m.Memory.BaseRva + minidumpOffset
			return m.reader.Read(binary.Pointer(offset), size)
		}

		minidumpOffset += memory64.DataSize
	}

	return nil, fmt.Errorf("Cannot find memory with address 0x%x in memory list.", start)
}

// MemoryReader

func (m Minidump) ProcessorArchitecture() windows.Arch {
	return m.SystemInfo.ProcessorArchitecture
}

func (m Minidump) BuildNumber() windows.BuildNumber {
	return m.SystemInfo.BuildNumber
}

func (m Minidump) ReadUInt32(ptr binary.Pointer) (uint32, error) {
	return utils.MemoryReaderUInt32(m, ptr)
}

func (m Minidump) ReadUInt64(ptr binary.Pointer) (uint64, error) {
	return utils.MemoryReaderUInt64(m, ptr)
}

func (m Minidump) ReadFileTime(ptr binary.Pointer) (time.Time, error) {
	return utils.MemoryReaderFileTime(m, ptr)
}

func (m Minidump) ReadStructure(ptr binary.Pointer, data interface{}) error {
	return utils.MemoryReaderStructure(m, ptr, m.ProcessorArchitecture().Isx64(), data)
}

func (m *Minidump) getPointer(ptr binary.Pointer) (binary.Pointer, error) {
	buf, err := m.Read(ptr, 4)
	if err != nil {
		return binary.Pointer(0), err
	}

	offset := binary.LittleEndian.Uint32(buf)

	if m.ProcessorArchitecture() == windows.ProcessorArchitectureAMD64 {
		return ptr.WithOffset(int64(offset) + 4), nil
	} else if m.ProcessorArchitecture() == windows.ProcessorArchitectureX86 {
		return binary.Pointer(uint64(offset)), nil
	} else {
		return binary.Pointer(0), fmt.Errorf("Minidump::getPointer is not support for ProcessorArchitecture %d.", m.ProcessorArchitecture())
	}
}

func (m *Minidump) ReadPointer(ptr binary.Pointer) (binary.Pointer, error) {
	if m.ProcessorArchitecture().Isx64() {
		p, err := m.ReadUInt64(ptr)
		return binary.Pointer(p), err
	} else {
		p, err := m.ReadUInt32(ptr)
		return binary.Pointer(p), err
	}
}

func (m Minidump) ReadFromPointer(ptr binary.Pointer, size uint32) ([]byte, error) {
	// fmt.Printf("ReadFromPointer(0x%x, %d)\n", ptr, size)
	newPtr, err := m.getPointer(ptr)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("ReadFromPointer newPtr: %x\n", newPtr)

	return m.Read(newPtr, size)
}

func (m *Minidump) ReadNextPointer(ptr binary.Pointer) (binary.Pointer, binary.Pointer, error) {
	newPtr, err := m.getPointer(ptr)
	if err != nil {
		return newPtr, newPtr, err
	}

	nextPtr, err := m.ReadPointer(newPtr)
	if err != nil {
		return nextPtr, nextPtr, err
	}

	return nextPtr, newPtr, nil
}

func (m Minidump) SearchPatternInModule(moduleName string, pattern []byte) (binary.Pointer, error) {
	module, err := m.findModuleByName(moduleName)
	if err != nil {
		return binary.Pointer(0), err
	}

	// TOOD: return all occurrence
	// positions := make([]uint64, 0)
	currentRva := m.Memory.BaseRva
	found := false
	patternSize := uint32(len(pattern))
	for _, memory64 := range m.Memory.MemoryRanges {
		if memory64.StartOfMemoryRange <= module.BaseOfImage && module.BaseOfImage < memory64.StartOfMemoryRange+memory64.DataSize {
			found = true
		}

		if module.BaseOfImage+uint64(module.SizeOfImage) < memory64.StartOfMemoryRange {
			break
		}

		if found && memory64.DataSize > uint64(patternSize) {
			for i := uint64(0); i < memory64.DataSize-uint64(patternSize); i++ {
				searchOffset := currentRva + i
				t, err := m.reader.Read(binary.Pointer(searchOffset), patternSize)
				if err != nil {
					return binary.Pointer(0), fmt.Errorf("Cannot search pattern in the memory.")
				}
				if bytes.Compare(pattern, t) == 0 {
					// positions = append(positions, memory64.StartOfMemoryRange + i)
					return binary.Pointer(memory64.StartOfMemoryRange + i), nil
				}
			}
		}

		currentRva += memory64.DataSize
	}

	return binary.Pointer(0), fmt.Errorf("Cannot find pattern in Minidump memory.")
}

func (m Minidump) GetModuleTimestamp(moduleName string) (uint64, error) {
	module, err := m.findModuleByName(moduleName)
	if err != nil {
		return uint64(0), err
	}

	return uint64(module.TimeDateStamp), nil
}
