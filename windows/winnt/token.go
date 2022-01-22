package winnt

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

type Token windows.Token

type TokenUser struct {
	User SIDAndAttributes
}

type LargeInteger int64

type TokenType uint32

const (
	TokenPrimary = iota
	TokenImpersonation
)

type SecurityImpersonationLevel uint32

const (
	SecurityAnonymous = iota
	SecurityIdentification
	SecurityImpersonation
	SecurityDelegation
)

type TokenStatistics struct {
	TokenId            windows.LUID
	AuthenticationId   windows.LUID
	ExpirationTime     LargeInteger
	TokenType          TokenType
	ImpersonationLevel SecurityImpersonationLevel
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         windows.LUID
}

type TokenGroupsAndPrivileges struct {
	SidCount            uint32
	SidLength           uint32
	Sids                *SIDAndAttributes
	RestrictedSidCount  uint32
	RestrictedSidLength uint32
	RestrictedSids      *SIDAndAttributes
	PrivilegeCount      uint32
	PrivilegeLength     uint32
	Privileges          *LUIDAndAttributes
	AuthenticationId    windows.LUID
}

func (t TokenType) String() string {
	if t == TokenPrimary {
		return "Primary"
	} else if t == TokenImpersonation {
		return "Impersonation"
	} else {
		return "Unknown"
	}
}

func (l SecurityImpersonationLevel) String() string {
	if l == SecurityAnonymous {
		return "Anonymous"
	} else if l == SecurityIdentification {
		return "Identification"
	} else if l == SecurityImpersonation {
		return "Impersonation"
	} else if l == SecurityDelegation {
		return "Delegation"
	} else {
		return "Unknown"
	}
}

func (t TokenGroupsAndPrivileges) AllSids() []SIDAndAttributes {
	// there is at least the current user SID
	return (*[(1 << 28) - 1]SIDAndAttributes)(unsafe.Pointer(t.Sids))[:t.SidCount:t.SidCount]
}

func (t TokenGroupsAndPrivileges) AllRestrictedSids() []SIDAndAttributes {
	if t.RestrictedSidCount > 0 {
		return (*[(1 << 28) - 1]SIDAndAttributes)(unsafe.Pointer(t.RestrictedSids))[:t.RestrictedSidCount:t.RestrictedSidCount]
	}

	return make([]SIDAndAttributes, 0)
}

func (t TokenGroupsAndPrivileges) AllPrivileges() []LUIDAndAttributes {
	if t.PrivilegeCount > 0 {
		return (*[(1 << 27) - 1]LUIDAndAttributes)(unsafe.Pointer(t.Privileges))[:t.PrivilegeCount:t.PrivilegeCount]
	}

	return make([]LUIDAndAttributes, 0)
}

func (t Token) getInfo(class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := windows.GetTokenInformation(windows.Token(t), class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if e != windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

func (t Token) GetTokenStatistics() (*TokenStatistics, error) {
	i, e := t.getInfo(windows.TokenStatistics, 56)
	if e != nil {
		return nil, e
	}
	return (*TokenStatistics)(i), nil
}

func (t Token) GetTokenUser() (*TokenUser, error) {
	i, e := t.getInfo(windows.TokenUser, 50)
	if e != nil {
		return nil, e
	}
	return (*TokenUser)(i), nil
}

func (t Token) GetTokenGroupsAndPrivileges() (*TokenGroupsAndPrivileges, error) {
	i, e := t.getInfo(windows.TokenGroupsAndPrivileges, 50)
	if e != nil {
		return nil, e
	}
	return (*TokenGroupsAndPrivileges)(i), nil
}
