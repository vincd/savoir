package utils

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

type SimpleMemoryReader interface {
	Read(ptr binary.Pointer, size uint32) ([]byte, error)
}

type MemoryReader interface {
	SimpleMemoryReader
	ProcessorArchitecture() windows.Arch
	BuildNumber() windows.BuildNumber
	ReadUInt32(ptr binary.Pointer) (uint32, error)
	ReadUInt64(ptr binary.Pointer) (uint64, error)
	ReadFileTime(ptr binary.Pointer) (time.Time, error)
	ReadStructure(ptr binary.Pointer, data interface{}) error
	ReadPointer(ptr binary.Pointer) (binary.Pointer, error)
	ReadFromPointer(ptr binary.Pointer, size uint32) ([]byte, error)
	ReadNextPointer(ptr binary.Pointer) (binary.Pointer, binary.Pointer, error)
	SearchPatternInModule(moduleName string, pattern []byte) (binary.Pointer, error)
}

func MemoryReaderUInt16(r SimpleMemoryReader, ptr binary.Pointer) (uint16, error) {
	buff, err := r.Read(ptr, 2)
	if err != nil {
		return 0, nil
	}

	return binary.LittleEndian.Uint16(buff), nil
}

func MemoryReaderUInt32(r SimpleMemoryReader, ptr binary.Pointer) (uint32, error) {
	buff, err := r.Read(ptr, 4)
	if err != nil {
		return 0, nil
	}

	return binary.LittleEndian.Uint32(buff), nil
}

func MemoryReaderUInt64(r SimpleMemoryReader, ptr binary.Pointer) (uint64, error) {
	buff, err := r.Read(ptr, 8)
	if err != nil {
		return 0, nil
	}

	return binary.LittleEndian.Uint64(buff), nil
}

func MemoryReaderArray(r SimpleMemoryReader, ptr binary.Pointer) ([]byte, error) {
	size, err := MemoryReaderUInt32(r, ptr)
	if err != nil {
		return nil, err
	}

	return r.Read(ptr.WithOffset(4), size)
}

func MemoryReaderStructure(r SimpleMemoryReader, ptr binary.Pointer, is64 bool, data interface{}) error {
	size := uint32(binary.Size(data, is64))
	buffer, err := r.Read(ptr, size)
	if err != nil {
		return err
	}

	if err := binary.Read(bytes.NewBuffer(buffer), binary.LittleEndian, is64, data); err != nil {
		return err
	}

	return nil
}

func MemoryReaderFileTime(r SimpleMemoryReader, ptr binary.Pointer) (time.Time, error) {
	buff, err := r.Read(ptr, 8)
	if err != nil {
		return time.Unix(0, 0), nil
	}

	ft := &windows.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(buff[:4]),
		HighDateTime: binary.LittleEndian.Uint32(buff[4:]),
	}

	return time.Unix(0, ft.Nanoseconds()), nil
}

func DumpMemory(r SimpleMemoryReader, ptr binary.Pointer, size uint32) {
	buff, err := r.Read(ptr, size)
	if err != nil {
		fmt.Printf("Error gettting memory from 0x%x (%d): %s", ptr, size, err)
	}

	fmt.Printf("Memory dump at 0x%x (%d)\n%s\n", ptr, ptr, hex.Dump(buff))
}

type BytesReader struct {
	buffer []byte
	Is64   bool
}

func NewBytesReader(buffer []byte, is64 bool) BytesReader {
	return BytesReader{
		buffer: buffer,
		Is64:   is64,
	}
}

func (r BytesReader) BuildNumber() windows.BuildNumber {
	return windows.BuildNumber(0)
}

func (r BytesReader) ProcessorArchitecture() windows.Arch {
	return windows.Arch(0)
}

func (r BytesReader) Read(ptr binary.Pointer, size uint32) ([]byte, error) {
	if uint64(len(r.buffer)) < ptr.U64()+uint64(size) {
		return nil, fmt.Errorf("Buffer is too small to read.")
	}

	return r.buffer[ptr : ptr.U64()+uint64(size)], nil
}

func (r BytesReader) ReadUInt32(ptr binary.Pointer) (uint32, error) {
	return MemoryReaderUInt32(r, ptr)
}

func (r BytesReader) ReadUInt64(ptr binary.Pointer) (uint64, error) {
	return MemoryReaderUInt64(r, ptr)
}

func (r BytesReader) ReadFileTime(ptr binary.Pointer) (time.Time, error) {
	return MemoryReaderFileTime(r, ptr)
}

func (r BytesReader) ReadStructure(ptr binary.Pointer, data interface{}) error {
	return MemoryReaderStructure(r, ptr, r.Is64, data)
}

func (r BytesReader) SearchPatternInModule(moduleName string, pattern []byte) (binary.Pointer, error) {
	return binary.Pointer(0), fmt.Errorf("Method BytesReader::SearchPatternInModule not implemented.")
}

func (r BytesReader) ReadFromPointer(ptr binary.Pointer, size uint32) ([]byte, error) {
	return nil, fmt.Errorf("Method BytesReader::ReadFromPointer not implemented.")
}

func (r BytesReader) ReadNextPointer(ptr binary.Pointer) (binary.Pointer, binary.Pointer, error) {
	return binary.Pointer(0), binary.Pointer(0), fmt.Errorf("Method BytesReader::ReadNextPointer not implemented.")
}

func (m BytesReader) ReadPointer(ptr binary.Pointer) (binary.Pointer, error) {
	return binary.Pointer(0), fmt.Errorf("Method BytesReader::ReadPointer not implemented.")
}
