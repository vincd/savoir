package registry

import (
	"fmt"
	"strings"
	"syscall"

	windows_registry "golang.org/x/sys/windows/registry"
)

type WindowsHive struct {
	Key  windows_registry.Key
	Base string
}

type WindowsKey struct {
	key  windows_registry.Key
	name string
}

func (key WindowsKey) Close() error {
	return key.key.Close()
}

func (key WindowsKey) ClassName() (string, error) {
	var classNameSize = uint32(256)
	var classNameBuffer = make([]uint16, classNameSize)

	err := syscall.RegQueryInfoKey(key.handle(), &classNameBuffer[0], &classNameSize, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return "", err
	}

	className := syscall.UTF16ToString(classNameBuffer[0:classNameSize])

	return string(className), nil
}

func (key WindowsKey) Name() string {
	return key.name[strings.LastIndex(key.name, "\\")+1:]
}

func (key WindowsKey) handle() syscall.Handle {
	return syscall.Handle(key.key)
}

func (key WindowsKey) EnumKey() ([]HiveKey, error) {
	keyInfo, err := key.key.Stat()
	if err != nil {
		return nil, err
	}

	subKeys := make([]HiveKey, 0)
	buf := make([]uint16, keyInfo.MaxSubKeyLen+1)
	for i := uint32(0); i < keyInfo.SubKeyCount; i++ {
		size := uint32(len(buf))
		if err := syscall.RegEnumKeyEx(key.handle(), i, &buf[0], &size, nil, nil, nil, nil); err != nil {
			return nil, fmt.Errorf("Cannot enum key %d: %s", i, err)
		}

		name := syscall.UTF16ToString(buf[0:size])
		subKey, err := windows_registry.OpenKey(key.key, name, windows_registry.QUERY_VALUE|windows_registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return nil, err
		}

		subKeys = append(subKeys, WindowsKey{
			key:  subKey,
			name: fmt.Sprintf("%s\\%s", key.name, name),
		})
	}

	return subKeys, nil
}

func (key WindowsKey) QueryValue(value string) ([]byte, error) {
	expectedSize, _, err := key.key.GetValue(value, nil)

	buff := make([]byte, expectedSize)
	size, _, err := key.key.GetValue(value, buff)
	if err != nil {
		return nil, err
	}

	if size != expectedSize {
		return nil, fmt.Errorf("Query value return a wrong size.")
	}

	return buff, nil
}

func NewWindowsHive(base string) (WindowsHive, error) {
	h := WindowsHive{
		Key:  windows_registry.LOCAL_MACHINE,
		Base: base,
	}

	return h, nil
}

func (h WindowsHive) OpenKey(path string) (HiveKey, error) {
	name := fmt.Sprintf("%s\\%s", h.Base, path)
	k, err := windows_registry.OpenKey(h.Key, name, windows_registry.QUERY_VALUE|windows_registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("Cannot open Registry key %s: %s", name, err)
	}

	wk := WindowsKey{
		key:  k,
		name: name,
	}

	return wk, nil
}
