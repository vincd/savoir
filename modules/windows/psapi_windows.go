package windows

import (
	"unsafe"

	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/psapi"
)


// Enumerate modules (dll) handles for a process
func EnumProcessModules(process sys_windows.Handle) ([]sys_windows.Handle, error) {
	modules := make([]sys_windows.Handle, 0x100)
	handleSize := uint32(unsafe.Sizeof(modules[0]))
	var needed uint32

	if err := psapi.EnumProcessModules(process, &modules[0], handleSize*uint32(len(modules)), &needed); err != nil {
		return nil, err
	}

	// We need more space
	n := int(needed / handleSize)
	if n > len(modules) {
		modules = make([]sys_windows.Handle, n)
		if err := psapi.EnumProcessModules(process, &modules[0], handleSize*uint32(len(modules)), &needed); err != nil {
			return nil, err
		}
	}

	return modules, nil
}