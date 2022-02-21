package minidump

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
)

const MINIDUMP_SIGNATURE = "MDMP"
const MINIDUMP_VERSION = 42899

type Minidump struct {
	reader     utils.MemoryReader
	Header     MinidumpHeader
	SystemInfo SystemInfo
	Modules    map[string]Module
	Memory     Memory64List
}

func NewMinidump(path string) (*Minidump, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	reader := utils.NewBytesReader(data, true)

	header := &MinidumpHeader{}
	if err := reader.ReadStructure(binary.Pointer(0), header); err != nil {
		return nil, err
	}

	if string(header.Signature[:]) != MINIDUMP_SIGNATURE || (header.Version&0xFFFF) != MINIDUMP_VERSION {
		return nil, fmt.Errorf("Invalid minidump Signature (%s) or Version (%d).", string(header.Signature[:]), (header.Version & 0xFFFF))
	}

	minidump := &Minidump{
		reader: reader,
		Header: *header,
	}

	systemInfo, err := minidump.getSystemInfo()
	if err != nil {
		return nil, err
	}
	minidump.SystemInfo = *systemInfo

	moduleList, err := minidump.getModuleList()
	if err != nil {
		return nil, err
	}

	minidump.Modules = make(map[string]Module)
	for _, module := range moduleList.Modules {
		moduleName, err := minidump.readStringUTF16(uint64(module.ModuleNameRva))
		if err != nil {
			return nil, err
		}

		minidump.Modules[moduleName] = module
	}

	memory64List, err := minidump.getMemory64List()
	if err != nil {
		return nil, err
	}

	minidump.Memory = *memory64List

	return minidump, nil
}

func (m *Minidump) readStream(streamType StreamType) (*Directory, error) {
	for i := uint32(0); i < m.Header.NumberOfStreams; i++ {
		streamDirectory := &Directory{}
		ptr := binary.Pointer(uint64(m.Header.StreamDirectoryRva) + uint64(i)*12)
		if err := m.reader.ReadStructure(ptr, streamDirectory); err != nil {
			return nil, err
		}

		if streamDirectory.StreamType == streamType {
			return streamDirectory, nil
		}
	}

	return nil, fmt.Errorf("Cannot find stream with type %d in minidump.", streamType)
}

func (m *Minidump) readStringUTF16(rva uint64) (string, error) {
	ptr := binary.Pointer(rva)
	size, err := m.reader.ReadUInt32(ptr)
	if err != nil {
		return "", err
	}

	buf, err := m.reader.Read(ptr.WithOffset(4), size)
	if err != nil {
		return "", err
	}

	s, err := utils.UTF16DecodeFromBytes(buf)
	if err != nil {
		return "", err
	}

	return s, nil
}

func (m *Minidump) getSystemInfo() (*SystemInfo, error) {
	stream, err := m.readStream(SystemInfoStream)
	if err != nil {
		return nil, err
	}

	systemInfo := &SystemInfo{}
	if err := m.reader.ReadStructure(binary.Pointer(stream.Location.Rva), systemInfo); err != nil {
		return nil, err
	}

	return systemInfo, nil
}

func (m *Minidump) getModuleList() (*ModuleList, error) {
	streamModuleList, err := m.readStream(ModuleListStream)
	if err != nil {
		return nil, err
	}

	numberOfModules, err := m.reader.ReadUInt32(binary.Pointer(streamModuleList.Location.Rva))
	if err != nil {
		return nil, err
	}

	moduleList := &ModuleList{
		NumberOfModules: numberOfModules,
		Modules:         make([]Module, 0),
	}

	// TODO: size is fixed
	for i := uint32(0); i < moduleList.NumberOfModules; i++ {
		offset := binary.Pointer(uint64(streamModuleList.Location.Rva) + 4 + uint64(i)*108)
		module := &Module{}
		if err := m.reader.ReadStructure(offset, module); err != nil {
			return nil, err
		}

		moduleList.Modules = append(moduleList.Modules, *module)
	}

	return moduleList, nil
}

func (m *Minidump) findModuleByName(targetModuleName string) (*Module, error) {
	for moduleName, module := range m.Modules {
		if strings.HasSuffix(strings.ToLower(moduleName), "\\"+targetModuleName) {
			return &module, nil
		}
	}

	return nil, fmt.Errorf("Cannot find module with name %s.", targetModuleName)
}

func (m *Minidump) getMemory64List() (*Memory64List, error) {
	stream, err := m.readStream(Memory64ListStream)
	if err != nil {
		return nil, err
	}

	numberOfMemoryRanges, err := m.reader.ReadUInt64(binary.Pointer(stream.Location.Rva))
	if err != nil {
		return nil, err
	}

	baseRva, err := m.reader.ReadUInt64(binary.Pointer(stream.Location.Rva + 8))
	if err != nil {
		return nil, err
	}

	memory64List := &Memory64List{
		NumberOfMemoryRanges: numberOfMemoryRanges,
		BaseRva:              baseRva,
		MemoryRanges:         make([]MemoryDescriptor64, 0),
	}

	for i := uint64(0); i < memory64List.NumberOfMemoryRanges; i++ {
		offset := uint64(stream.Location.Rva) + 16 + i*16
		memoryDescriptor64 := &MemoryDescriptor64{}
		if err := m.reader.ReadStructure(binary.Pointer(offset), memoryDescriptor64); err != nil {
			return nil, err
		}

		memory64List.MemoryRanges = append(memory64List.MemoryRanges, *memoryDescriptor64)
	}

	return memory64List, nil
}
