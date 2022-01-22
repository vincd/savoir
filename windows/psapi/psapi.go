package psapi

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modpsapi = windows.NewLazySystemDLL("psapi.dll")
)

var (
	procEnumProcessModules   = modpsapi.NewProc("EnumProcessModules")
	procGetModuleInformation = modpsapi.NewProc("GetModuleInformation")
)

type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func (mi ModuleInfo) String() string {
	return fmt.Sprintf("ModuleInfo(0x%x, %d, 0x%x)", mi.BaseOfDll, mi.SizeOfImage, mi.EntryPoint)
}

func EnumAllProcessModules(process windows.Handle) ([]windows.Handle, error) {
	modules := make([]windows.Handle, 0x100)
	handleSize := uint32(unsafe.Sizeof(modules[0]))
	var needed uint32

	err := EnumProcessModules(process, &modules[0], handleSize*uint32(len(modules)), &needed)
	if err != nil {
		return nil, err
	}

	// We need more space
	n := int(needed / handleSize)
	if n > len(modules) {
		modules = make([]windows.Handle, n)
		err := EnumProcessModules(process, &modules[0], handleSize*uint32(len(modules)), &needed)
		if err != nil {
			return nil, err
		}
	}

	return modules, nil
}

func EnumProcessModules(process windows.Handle, modules *windows.Handle, cb uint32, needed *uint32) error {
	r0, _, e1 := procEnumProcessModules.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(modules)),
		uintptr(cb),
		uintptr(unsafe.Pointer(needed)),
	)

	if r0 == 0 {
		if e1 != nil {
			return e1
		}
		return syscall.EINVAL
	}

	return nil
}

func GetModuleInformation(process windows.Handle, module windows.Handle, modinfo *ModuleInfo) error {
	r0, _, e1 := procGetModuleInformation.Call(uintptr(process), uintptr(module), uintptr(unsafe.Pointer(modinfo)), uintptr(unsafe.Sizeof(*modinfo)))
	if r0 == 0 {
		return e1
	}

	return nil
}
