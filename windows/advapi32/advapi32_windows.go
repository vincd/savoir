//go:build windows
// +build windows

package advapi32

import (
	"golang.org/x/sys/windows"
)

var modadvapi32 = windows.NewLazyDLL("advapi32.dll")
