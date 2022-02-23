//go:build windows
// +build windows

package process

import (
	"bytes"
	encodingBinary "encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	swindows "github.com/vincd/savoir/windows"
	"github.com/vincd/savoir/windows/kernel32"
)

type Module struct {
	path        string
	baseAddress binary.Pointer
	size        uint32
}

func (m Module) String() string {
	return fmt.Sprintf("%s: from 0x%x to 0x%x (0x%x)", m.path, m.baseAddress, m.baseAddress.WithOffset(int64(m.size)), m.size)
}

type Page struct {
	baseAddress       binary.Pointer
	size              uint32
	allocationProtect uint32
}

func (p Page) String() string {
	return fmt.Sprintf("Page from 0x%x to 0x%x (0x%x) with protection: 0x%x", p.baseAddress, p.baseAddress.WithOffset(int64(p.size)), p.size, p.allocationProtect)
}

func (p Page) search(proc *Process, pattern []byte) (binary.Pointer, error) {
	data, err := proc.Read(p.baseAddress.ToUIntPtr(), uint64(p.size))
	if err != nil {
		return binary.Pointer(0), err
	}

	patternSize := int64(len(pattern))
	for i := int64(0); i < int64(p.size)-patternSize; i++ {
		if bytes.Compare(pattern, data[i:i+patternSize]) == 0 {
			return p.baseAddress.WithOffset(i), nil
		}
	}

	return binary.Pointer(0), fmt.Errorf("cannot find pattern in module memory")
}

type ProcessReader struct {
	process      *Process
	MajorVersion uint32
	MinorVersion uint32
	buildNumber  swindows.BuildNumber
	arch         swindows.Arch
	Modules      []Module
	Pages        []Page
}

func newProcessReaderWithProcess(process *Process) (*ProcessReader, error) {
	// Get Windows numbers to parse the process
	majorVersion, minorVersion, buildNumber := sys_windows.RtlGetNtVersionNumbers()
	si := kernel32.GetSystemInfo()

	p := &ProcessReader{
		process:      process,
		MajorVersion: majorVersion,
		MinorVersion: minorVersion,
		buildNumber:  swindows.BuildNumber(buildNumber),
		arch:         swindows.Arch(si.ProcessorArchitecture),
		Modules:      make([]Module, 0),
		Pages:        make([]Page, 0),
	}

	moduleInfos, err := p.process.Modules()
	if err != nil {
		return nil, err
	}

	for moduleFilename, mi := range moduleInfos {
		p.Modules = append(p.Modules, Module{
			path:        moduleFilename,
			baseAddress: binary.Pointer(mi.BaseOfDll),
			size:        mi.SizeOfImage,
		})
	}

	currentAddress := si.MinimumApplicationAddress
	for currentAddress < si.MaximumApplicationAddress {
		pageInfo, err := kernel32.VirtualQueryEx(p.process.Handle(), currentAddress)
		if err != nil {
			fmt.Printf("cannot query page at 0x%x: %s\n", currentAddress, err)
			continue
		}

		p.Pages = append(p.Pages, Page{
			baseAddress:       binary.Pointer(pageInfo.BaseAddress),
			size:              uint32(pageInfo.RegionSize),
			allocationProtect: pageInfo.AllocationProtect,
		})
		currentAddress += pageInfo.RegionSize
	}

	return p, nil
}

func NewProcessReaderWithHandle(name string, pId uint32, handle sys_windows.Handle) (*ProcessReader, error) {
	p, err := NewProcessWithHandle(handle)
	if err != nil {
		return nil, err
	}

	return newProcessReaderWithProcess(p)
}

func NewProcessReader(processName string) (*ProcessReader, error) {
	p, err := NewProcessWithName(processName, sys_windows.PROCESS_VM_READ|sys_windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return nil, err
	}

	return newProcessReaderWithProcess(p)
}

func (p ProcessReader) String() string {
	return fmt.Sprintf("ProcessReader: %s", p.process.String())
}

func (p ProcessReader) Close() {
	p.process.Close()
}

func (p ProcessReader) Read(ptr binary.Pointer, size uint32) ([]byte, error) {
	for _, page := range p.Pages {
		if page.baseAddress <= ptr && ptr < page.baseAddress.WithOffset(int64(page.size)) {
			return p.process.Read(ptr.ToUIntPtr(), uint64(size))
		}
	}

	return nil, fmt.Errorf("cannot find address 0x%x in current process pages", ptr)
}

func (p ProcessReader) ProcessorArchitecture() swindows.Arch {
	return p.arch
}

func (p ProcessReader) BuildNumber() swindows.BuildNumber {
	return p.buildNumber
}

func (p ProcessReader) ReadUInt32(ptr binary.Pointer) (uint32, error) {
	return utils.MemoryReaderUInt32(p, ptr)
}

func (p ProcessReader) ReadUInt64(ptr binary.Pointer) (uint64, error) {
	return utils.MemoryReaderUInt64(p, ptr)
}

func (p ProcessReader) ReadFileTime(ptr binary.Pointer) (time.Time, error) {
	return utils.MemoryReaderFileTime(p, ptr)
}

func (p ProcessReader) ReadStructure(ptr binary.Pointer, data interface{}) error {
	return utils.MemoryReaderStructure(p, ptr, true, data)
}

func (p ProcessReader) findModuleByName(targetModuleName string) (*Module, error) {
	for _, module := range p.Modules {
		if strings.HasSuffix(strings.ToLower(module.path), "\\"+targetModuleName) {
			return &module, nil
		}
	}

	return nil, fmt.Errorf("cannot find module with name %s", targetModuleName)
}

func (p ProcessReader) SearchPatternInModule(moduleName string, pattern []byte) (binary.Pointer, error) {
	module, err := p.findModuleByName(moduleName)
	if err != nil {
		return binary.Pointer(0), err
	}

	for _, page := range p.Pages {
		if module.baseAddress <= page.baseAddress && page.baseAddress < module.baseAddress.WithOffset(int64(module.size)) {
			ptr, err := page.search(p.process, pattern)
			if err == nil {
				return ptr, nil
			}
		}
	}

	return binary.Pointer(0), fmt.Errorf("cannot find pattern in module memory: %x", pattern)
}

// Get Module creation time in milliseconds
func (m ProcessReader) GetModuleTimestamp(moduleName string) (uint64, error) {
	module, err := m.findModuleByName(moduleName)
	if err != nil {
		return uint64(0), err
	}

	// we recover the creation timestamp for a module when we need it
	info, err := os.Stat(module.path)
	if err != nil {
		return uint64(0), err
	}

	// FileInfo.Sys() returns the System data structure (Win32FileAttributeData on Windows)
	// We use this structure to recover the `CreationTime`.
	win32FileAttribute := info.Sys().(*syscall.Win32FileAttributeData)
	ts := win32FileAttribute.CreationTime.Nanoseconds() / 1000 / 1000

	return uint64(ts), nil
}

func (p ProcessReader) getPointer(ptr binary.Pointer) (binary.Pointer, error) {
	buf, err := p.Read(ptr, 4)
	if err != nil {
		return binary.Pointer(0), err
	}

	offset := encodingBinary.LittleEndian.Uint32(buf)

	if p.ProcessorArchitecture().Isx64() {
		return ptr.WithOffset(int64(offset) + 4), nil
	} else if p.ProcessorArchitecture().Isx86() {
		return binary.Pointer(uint64(offset)), nil
	} else {
		return binary.Pointer(0), fmt.Errorf("cannot get pointer for processor architecture %d", p.ProcessorArchitecture())
	}
}

func (p ProcessReader) ReadPointer(ptr binary.Pointer) (binary.Pointer, error) {
	if p.ProcessorArchitecture().Isx64() {
		p, err := p.ReadUInt64(ptr)
		return binary.Pointer(p), err
	} else {
		p, err := p.ReadUInt32(ptr)
		return binary.Pointer(p), err
	}
}

func (p ProcessReader) ReadFromPointer(ptr binary.Pointer, size uint32) ([]byte, error) {
	newPtr, err := p.getPointer(ptr)
	if err != nil {
		return nil, err
	}

	return p.Read(newPtr, size)
}

func (p ProcessReader) ReadNextPointer(ptr binary.Pointer) (binary.Pointer, binary.Pointer, error) {
	newPtr, err := p.getPointer(ptr)
	if err != nil {
		return newPtr, newPtr, err
	}

	nextPtr, err := p.ReadPointer(newPtr)
	if err != nil {
		return nextPtr, nextPtr, err
	}

	return nextPtr, newPtr, nil
}
