package tokens

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/windows/sid"
	"github.com/vincd/savoir/modules/windows/luid"
)

type Token windows.Token

type TokenUser struct {
	User sid.SIDAndAttributes
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
	Sids                *sid.SIDAndAttributes
	RestrictedSidCount  uint32
	RestrictedSidLength uint32
	RestrictedSids      *sid.SIDAndAttributes
	PrivilegeCount      uint32
	PrivilegeLength     uint32
	Privileges          *luid.LUIDAndAttributes
	AuthenticationId    windows.LUID
}

func (t Token) Close() {
	windows.Token(t).Close()
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

func (t TokenGroupsAndPrivileges) AllSids() []sid.SIDAndAttributes {
	// there is at least the current user SID
	return (*[(1 << 28) - 1]sid.SIDAndAttributes)(unsafe.Pointer(t.Sids))[:t.SidCount:t.SidCount]
}

func (t TokenGroupsAndPrivileges) AllRestrictedSids() []sid.SIDAndAttributes {
	if t.RestrictedSidCount > 0 {
		return (*[(1 << 28) - 1]sid.SIDAndAttributes)(unsafe.Pointer(t.RestrictedSids))[:t.RestrictedSidCount:t.RestrictedSidCount]
	}

	return make([]sid.SIDAndAttributes, 0)
}

func (t TokenGroupsAndPrivileges) AllPrivileges() []luid.LUIDAndAttributes {
	if t.PrivilegeCount > 0 {
		return (*[(1 << 27) - 1]luid.LUIDAndAttributes)(unsafe.Pointer(t.Privileges))[:t.PrivilegeCount:t.PrivilegeCount]
	}

	return make([]luid.LUIDAndAttributes, 0)
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

func (t Token) DisplayInformation() error {
	tokenStatistics, err := t.GetTokenStatistics()
	if err != nil {
		return err
	}

	fmt.Printf("{%x;%08x}\n", tokenStatistics.AuthenticationId.HighPart, tokenStatistics.AuthenticationId.LowPart)

	tokenUser, err := t.GetTokenUser()
	if err != nil {
		return err
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return err
	}
	fmt.Printf("User: %s\\%s (%s) (%02dg,%02dp) %s\n", domain, account, tokenUser.User.Sid.String(), tokenStatistics.GroupCount, tokenStatistics.PrivilegeCount, tokenStatistics.TokenType.String())

	if tokenStatistics.TokenType == TokenImpersonation {
		fmt.Printf(" (%s)\n", tokenStatistics.ImpersonationLevel.String())
	}

	tokenGroupsAndPrivileges, err := t.GetTokenGroupsAndPrivileges()
	if err != nil {
		return err
	}

	// The first one is the current user
	for _, sid := range tokenGroupsAndPrivileges.AllSids()[1:] {
		fmt.Printf("   Group: %s\n", sid.String())
	}

	for _, sid := range tokenGroupsAndPrivileges.AllRestrictedSids() {
		fmt.Printf("    Rest: %s\n", sid.String())
	}

	for _, priv := range tokenGroupsAndPrivileges.AllPrivileges() {
		fmt.Printf("    Priv: %s\n", priv.String())
	}

	return nil
}

func (t Token) DuplicateTokenEx(desiredAccess uint32, tokenAttributes *windows.SecurityAttributes, impersonationLevel uint32, tokenType uint32) (*Token, error) {
	var duplicatedToken windows.Token
	if err := windows.DuplicateTokenEx(windows.Token(t), desiredAccess, tokenAttributes, impersonationLevel,tokenType, &duplicatedToken); err != nil {
		return nil, err
	}

	token := Token(duplicatedToken)
	return &token, nil
}
