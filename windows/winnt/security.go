package winnt

import (
	"fmt"
	"golang.org/x/sys/windows"
)

const (
	SE_GROUP_MANDATORY          = 0x00000001
	SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
	SE_GROUP_ENABLED            = 0x00000004
	SE_GROUP_OWNER              = 0x00000008
	SE_GROUP_USE_FOR_DENY_ONLY  = 0x00000010
	SE_GROUP_INTEGRITY          = 0x00000020
	SE_GROUP_INTEGRITY_ENABLED  = 0x00000040
	SE_GROUP_LOGON_ID           = 0xC0000000
	SE_GROUP_RESOURCE           = 0x20000000
	SE_GROUP_VALID_ATTRIBUTES   = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER | SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_LOGON_ID | SE_GROUP_RESOURCE | SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED
)

type SIDAndAttributes struct {
	Sid        *windows.SID
	Attributes uint32
}

func (s SIDAndAttributes) IsMandatory() bool {
	return (s.Attributes & SE_GROUP_MANDATORY) > 0
}

func (s SIDAndAttributes) IsEnabledByDefault() bool {
	return (s.Attributes & SE_GROUP_ENABLED_BY_DEFAULT) > 0
}

func (s SIDAndAttributes) IsEnabled() bool {
	return (s.Attributes & SE_GROUP_ENABLED) > 0
}

func (s SIDAndAttributes) IsOwner() bool {
	return (s.Attributes & SE_GROUP_OWNER) > 0
}

func (s SIDAndAttributes) IsUseForDenyOnly() bool {
	return (s.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) > 0
}

func (s SIDAndAttributes) IsIntegrity() bool {
	return (s.Attributes & SE_GROUP_INTEGRITY) > 0
}

func (s SIDAndAttributes) IsIntegrityEnabled() bool {
	return (s.Attributes & SE_GROUP_INTEGRITY_ENABLED) > 0
}

func (s SIDAndAttributes) IsLogonId() bool {
	return (s.Attributes & SE_GROUP_LOGON_ID) > 0
}

func (s SIDAndAttributes) IsRessource() bool {
	return (s.Attributes & SE_GROUP_RESOURCE) > 0
}

func (s SIDAndAttributes) String() string {
	o := ""

	o += "["
	if s.IsMandatory() {
		o += "M"
	} else {
		o += " "
	}
	if s.IsEnabledByDefault() {
		o += "D"
	} else {
		o += " "
	}
	if s.IsEnabled() {
		o += "E"
	} else {
		o += " "
	}
	if s.IsOwner() {
		o += "O"
	} else {
		o += " "
	}
	if s.IsUseForDenyOnly() {
		o += "U"
	} else {
		o += " "
	}
	if s.IsLogonId() {
		o += "L"
	} else {
		o += " "
	}
	if s.IsRessource() {
		o += "R"
	} else {
		o += " "
	}
	o += "] "

	account, domain, _, err := s.Sid.LookupAccount("")
	if err != nil {
		o += fmt.Sprintf("%s", s.Sid.String())
	} else if len(domain) > 0 {
		o += fmt.Sprintf("%s\\%s", domain, account)
	} else {
		o += account
	}

	return o
}
