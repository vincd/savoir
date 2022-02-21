package ntsecapi

import (
	"golang.org/x/sys/windows"
)

type LsaEnumerationHandle uint64
type LsaEnumerationInformation struct {
	Sid *windows.SID
}
