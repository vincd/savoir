package msv

import (
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows/ntdll"
)

type KiwiMsv10List51 struct {
	Flink                   binary.Pointer
	Blink                   binary.Pointer
	LocallyUniqueIdentifier uint64
	UserName                ntdll.LsaUnicodeString
	Domain                  ntdll.LsaUnicodeString
	Unk0                    binary.Pointer
	Unk1                    binary.Pointer
	Sid                     binary.Pointer
	LogonType               uint32
	Session                 uint32
	_                       uint64
	LogonTime               uint64
	LogonServer             ntdll.LsaUnicodeString
	Credentials             binary.Pointer
	Unk19                   binary.Pointer
	Unk20                   binary.Pointer
	Unk21                   binary.Pointer
	Unk22                   binary.Pointer
	Unk23                   uint32
	CredentialManager       binary.Pointer
}

type KiwiMsv10List52 struct {
	Flink                   binary.Pointer
	Blink                   binary.Pointer
	LocallyUniqueIdentifier uint64
	UserName                ntdll.LsaUnicodeString
	Domain                  ntdll.LsaUnicodeString
	Unk0                    binary.Pointer
	Unk1                    binary.Pointer
	Sid                     binary.Pointer
	LogonType               uint32
	Session                 uint32
	LogonTime               uint64
	LogonServer             ntdll.LsaUnicodeString
	Credentials             binary.Pointer
	Unk19                   uint32
	Unk20                   binary.Pointer
	Unk21                   binary.Pointer
	Unk22                   uint32
	CredentialManager       binary.Pointer
}

type KiwiMsv10List60 struct {
	Flink                            binary.Pointer
	Blink                            binary.Pointer
	_                                uint32
	Unk0                             binary.Pointer
	Unk1                             uint32
	_                                uint32
	Unk2                             binary.Pointer
	Unk3                             uint32
	Unk4                             uint32
	Unk5                             uint32
	_                                uint32
	HSemaphore6                      binary.Pointer
	_                                uint32
	Unk7                             binary.Pointer
	_                                uint32
	HSemaphore8                      binary.Pointer
	_                                uint32
	Unk9                             binary.Pointer
	_                                uint32
	Unk10                            binary.Pointer
	Unk11                            uint32
	Unk12                            uint32
	_                                uint32
	Unk13                            binary.Pointer
	_                                uint32
	LocallyUniqueIdentifier          uint64
	SecondaryLocallyUniqueIdentifier uint64
	_                                uint32
	UserName                         ntdll.LsaUnicodeString
	Domain                           ntdll.LsaUnicodeString
	Unk14                            binary.Pointer
	Unk15                            binary.Pointer
	Sid                              binary.Pointer
	LogonType                        uint32
	Session                          uint32
	_                                uint64
	LogonTime                        uint64
	LogonServer                      ntdll.LsaUnicodeString
	Credentials                      binary.Pointer
	Unk19                            uint32
	_                                uint32
	Unk20                            binary.Pointer
	Unk21                            binary.Pointer
	Unk22                            binary.Pointer
	Unk23                            uint32
	_                                uint32
	CredentialManager                binary.Pointer
}

type KiwiMsv10List61 struct {
	Flink                            binary.Pointer
	Blink                            binary.Pointer
	Unk0                             binary.Pointer
	Unk1                             uint32
	_                                uint32
	Unk2                             binary.Pointer
	Unk3                             uint32
	Unk4                             uint32
	Unk5                             uint32
	_                                uint32
	HSemaphore6                      binary.Pointer
	Unk7                             binary.Pointer
	HSemaphore8                      binary.Pointer
	Unk9                             binary.Pointer
	Unk10                            binary.Pointer
	Unk11                            uint32
	Unk12                            uint32
	Unk13                            binary.Pointer
	LocallyUniqueIdentifier          uint64
	SecondaryLocallyUniqueIdentifier uint64
	UserName                         ntdll.LsaUnicodeString
	Domain                           ntdll.LsaUnicodeString
	Unk14                            binary.Pointer
	Unk15                            binary.Pointer
	Sid                              binary.Pointer
	LogonType                        uint32
	Session                          uint32
	_                                uint64 `align:"8"`
	LogonTime                        uint64
	LogonServer                      ntdll.LsaUnicodeString
	Credentials                      binary.Pointer
	Unk19                            binary.Pointer
	Unk20                            binary.Pointer
	Unk21                            binary.Pointer
	Unk22                            uint32
	_                                uint32
	CredentialManager                binary.Pointer
}

type KiwiMsv10List61AntiMimikatz struct {
	Flink                            binary.Pointer
	Blink                            binary.Pointer
	Unk0                             binary.Pointer
	Unk1                             uint32
	_                                uint32
	Unk2                             binary.Pointer
	Unk3                             uint32
	Unk4                             uint32
	Unk5                             uint32
	_                                uint32
	HSemaphore6                      binary.Pointer
	Unk7                             binary.Pointer
	HSemaphore8                      binary.Pointer
	Unk9                             binary.Pointer
	Unk10                            binary.Pointer
	Unk11                            uint32
	Unk12                            uint32
	Unk13                            binary.Pointer
	LocallyUniqueIdentifier          uint64
	SecondaryLocallyUniqueIdentifier uint64
	waza                             [12]byte
	_                                uint32
	UserName                         ntdll.LsaUnicodeString
	Domain                           ntdll.LsaUnicodeString
	Unk14                            binary.Pointer
	Unk15                            binary.Pointer
	Sid                              binary.Pointer
	LogonType                        uint32
	Session                          uint32
	_                                uint64 `align:"8"`
	LogonTime                        uint64
	LogonServer                      ntdll.LsaUnicodeString
	Credentials                      binary.Pointer
	Unk19                            binary.Pointer
	Unk20                            binary.Pointer
	Unk21                            binary.Pointer
	Unk22                            uint32
	_                                uint32
	CredentialManager                binary.Pointer
}

type KiwiMsv10List62 struct {
	Flink                            binary.Pointer
	Blink                            binary.Pointer
	Unk0                             binary.Pointer
	Unk1                             uint32
	_                                uint32
	Unk2                             binary.Pointer
	Unk3                             uint32
	Unk4                             uint32
	Unk5                             uint32
	HSemaphore6                      binary.Pointer
	Unk7                             binary.Pointer
	HSemaphore8                      binary.Pointer
	Unk9                             binary.Pointer
	Unk10                            binary.Pointer
	Unk11                            uint32
	Unk12                            uint32
	Unk13                            binary.Pointer
	LocallyUniqueIdentifier          uint64
	SecondaryLocallyUniqueIdentifier uint64
	UserName                         ntdll.LsaUnicodeString
	Domain                           ntdll.LsaUnicodeString
	Unk14                            binary.Pointer
	Unk15                            binary.Pointer
	Type                             ntdll.LsaUnicodeString
	Sid                              binary.Pointer
	LogonType                        uint32
	Unk18                            binary.Pointer
	Session                          uint32
	LogonTime                        uint64
	LogonServer                      ntdll.LsaUnicodeString
	Credentials                      binary.Pointer
	Unk19                            binary.Pointer
	Unk20                            binary.Pointer
	Unk21                            binary.Pointer
	Unk22                            uint32
	Unk23                            uint32
	Unk24                            uint32
	Unk25                            uint32
	Unk26                            uint32
	Unk27                            binary.Pointer
	Unk28                            binary.Pointer
	Unk29                            binary.Pointer
	CredentialManager                binary.Pointer
}

type KiwiMsv10List63 struct {
	Flink                            binary.Pointer
	Blink                            binary.Pointer
	Unk0                             binary.Pointer
	Unk1                             uint32 // 0FFFFFFFFh
	_                                uint32
	Unk2                             binary.Pointer // 0
	Unk3                             uint32         // 0
	Unk4                             uint32         // 0
	Unk5                             uint32         // 0A0007D0h
	_                                uint32
	HSemaphore6                      binary.Pointer // 0F9Ch
	Unk7                             binary.Pointer // 0
	HSemaphore8                      binary.Pointer // 0FB8h
	Unk9                             binary.Pointer // 0
	Unk10                            binary.Pointer // 0
	Unk11                            uint32         // 0
	Unk12                            uint32         // 0
	Unk13                            binary.Pointer // Unk_2C0A28
	_                                uint32
	LocallyUniqueIdentifier          uint64
	SecondaryLocallyUniqueIdentifier uint64
	Waza                             [12]byte
	_                                uint32
	UserName                         ntdll.LsaUnicodeString
	Domain                           ntdll.LsaUnicodeString
	Unk14                            binary.Pointer
	Unk15                            binary.Pointer
	Type                             ntdll.LsaUnicodeString
	Sid                              binary.Pointer
	LogonType                        uint32
	_                                uint32
	Unk18                            binary.Pointer
	Session                          uint32
	_                                uint32
	LogonTime                        uint64
	LogonServer                      ntdll.LsaUnicodeString
	Credentials                      binary.Pointer
	Unk19                            binary.Pointer
	Unk20                            binary.Pointer
	Unk21                            binary.Pointer
	Unk22                            uint32
	Unk23                            uint32
	Unk24                            uint32
	Unk25                            uint32
	Unk26                            uint32
	_                                uint32
	Unk27                            binary.Pointer
	Unk28                            binary.Pointer
	Unk29                            binary.Pointer
	CredentialManager                binary.Pointer
}

type ANSI_STRING struct {
	Length        uint16
	MaximumLength uint16
	_             uint32
	BufferPointer binary.Pointer
}

type KiwiMsv10Credentials struct {
	Next                    binary.Pointer
	AuthenticationPackageId uint32
	_                       uint32
	PrimaryCredentials      binary.Pointer
}

type KiwiMSV10PrimaryCredentials struct {
	Next        binary.Pointer
	Primary     ANSI_STRING
	Credentials ntdll.LsaUnicodeString
}

type MSV1_0_PRIMARY_CREDENTIAL struct {
	LogonDomainName ntdll.LsaUnicodeString
	UserName        ntdll.LsaUnicodeString
	NtOwfPassword   [16]byte
	LmOwfPassword   [16]byte
	ShaOwPassword   [20]byte
	IsNtOwfPassword bool
	IsLmOwfPassword bool
	IsShaOwPassword bool
	/* buffer */
}

type MSV1_0_PRIMARY_CREDENTIAL_10_OLD struct {
	LogonDomainName ntdll.LsaUnicodeString
	UserName        ntdll.LsaUnicodeString
	IsIso           bool
	IsNtOwfPassword bool
	IsLmOwfPassword bool
	IsShaOwPassword bool
	Align0          byte
	Align1          byte
	NtOwfPassword   [16]byte
	LmOwfPassword   [16]byte
	ShaOwPassword   [20]byte
	/* buffer */
}

type MSV1_0_PRIMARY_CREDENTIAL_10 struct {
	LogonDomainName ntdll.LsaUnicodeString
	UserName        ntdll.LsaUnicodeString
	IsIso           bool
	IsNtOwfPassword bool
	IsLmOwfPassword bool
	IsShaOwPassword bool
	Align0          byte
	Align1          byte
	Align2          byte
	Align3          byte
	NtOwfPassword   [16]byte
	LmOwfPassword   [16]byte
	ShaOwPassword   [20]byte
	/* buffer */
}

type MSV1_0_PRIMARY_CREDENTIAL_10_1607 struct {
	LogonDomainName    ntdll.LsaUnicodeString
	UserName           ntdll.LsaUnicodeString
	PNtlmCredIsoInProc binary.Pointer
	IsIso              bool
	IsNtOwfPassword    bool
	IsLmOwfPassword    bool
	IsShaOwPassword    bool
	IsDPAPIProtected   bool
	Align0             byte
	Align1             byte
	Align2             byte
	UnkD               uint32
	IsoSize            uint16
	DPAPIProtected     [16]byte
	Align3             uint32
	NtOwfPassword      [16]byte
	LmOwfPassword      [16]byte
	ShaOwPassword      [20]byte
	/* buffer */
}

type Msv10PrimaryCredentialStrange struct {
	Unk1                   uint16
	Unk2                   uint16
	UnkTag                 uint32
	Unk3                   uint32
	Unk4                   [40]byte
	LengthOfNtOwfPassword  uint32
	NtOwfPassword          [16]byte
	LengthOfShaOwfPassword uint32
	ShaOwPassword          [20]byte
}
