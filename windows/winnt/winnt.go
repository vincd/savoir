//go:build windows
// +build windows

package winnt

import (
	"syscall"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
)
