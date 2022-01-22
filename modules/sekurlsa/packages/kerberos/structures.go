package kerberos

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
	"github.com/vincd/savoir/windows/ntdll"
)

type KiwiKerberosLogonSession51 struct {
	UsageCount              uint32
	_                       uint32
	Unk0                    ntdll.ListEntry
	Unk1                    ntdll.ListEntry
	Unk2                    binary.Pointer
	Unk3                    uint32
	Unk4                    uint32
	Unk5                    binary.Pointer
	Unk6                    binary.Pointer
	Unk7                    binary.Pointer
	LocallyUniqueIdentifier uint64
	Unk8                    windows.Filetime
	Unk9                    binary.Pointer
	Unk10                   uint32 // filetime.1 ?
	Unk11                   uint32 // filetime.2 ?
	Unk12                   binary.Pointer
	Unk13                   binary.Pointer
	Unk14                   binary.Pointer
	Credentials             globals.KiwiGenericPrimaryCredential
	Unk15                   uint32
	Unk16                   uint32
	Unk17                   uint32
	Unk18                   uint32
	Unk19                   binary.Pointer
	Unk20                   binary.Pointer
	Unk21                   binary.Pointer
	Unk22                   binary.Pointer
	KeyList                 binary.Pointer
	Unk24                   binary.Pointer
	Tickets1                ntdll.ListEntry
	Tickets2                ntdll.ListEntry
	Tickets3                ntdll.ListEntry
	SmartcardInfos          binary.Pointer
}

type KiwiKerberosLogonSession struct {
	UsageCount              uint32
	_                       uint32
	Unk0                    ntdll.ListEntry
	Unk1                    binary.Pointer
	Unk2                    uint32
	Unk3                    uint32
	Unk4                    binary.Pointer
	Unk5                    binary.Pointer
	Unk6                    binary.Pointer
	LocallyUniqueIdentifier uint64
	_                       uint64 `align:"8"`
	Unk7                    windows.Filetime
	Unk8                    binary.Pointer
	Unk9                    uint32
	Unk10                   uint32
	Unk11                   binary.Pointer
	Unk12                   binary.Pointer
	Unk13                   binary.Pointer
	Credentials             globals.KiwiGenericPrimaryCredential
	Unk14                   uint32
	Unk15                   uint32
	Unk16                   uint32
	Unk17                   uint32
	Unk18                   binary.Pointer
	Unk19                   binary.Pointer
	Unk20                   binary.Pointer
	Unk21                   binary.Pointer
	KeyList                 binary.Pointer
	Unk23                   binary.Pointer
	Tickets1                ntdll.ListEntry
	Unk24                   windows.Filetime
	Tickets2                ntdll.ListEntry
	Unk25                   windows.Filetime
	Tickets3                ntdll.ListEntry
	Unk26                   windows.Filetime
	SmartcardInfos          binary.Pointer
}

type KiwiKerberosLogonSession10 struct {
	UsageCount              uint32
	_                       uint32
	Unk0                    ntdll.ListEntry
	Unk1                    binary.Pointer
	Unk1b                   uint32
	Unk2                    windows.Filetime
	Unk4                    binary.Pointer
	Unk5                    binary.Pointer
	Unk6                    binary.Pointer
	LocallyUniqueIdentifier uint64
	Unk7                    windows.Filetime
	Unk8                    binary.Pointer
	Unk8b                   uint32
	_                       uint32
	Unk9                    windows.Filetime
	Unk11                   binary.Pointer
	Unk12                   binary.Pointer
	Unk13                   binary.Pointer
	Credentials             KiwiKerberosPrimaryCredential10
	Unk14                   uint32
	Unk15                   uint32
	Unk16                   uint32
	Unk17                   uint32
	// Unk18          uint64
	Unk19          binary.Pointer
	Unk20          binary.Pointer
	Unk21          binary.Pointer
	Unk22          binary.Pointer
	Unk23          binary.Pointer
	Unk24          binary.Pointer
	Unk25          binary.Pointer
	KeyList        binary.Pointer
	Unk26          binary.Pointer
	Tickets1       ntdll.ListEntry
	Unk27          windows.Filetime
	Tickets2       ntdll.ListEntry
	Unk28          windows.Filetime
	Tickets3       ntdll.ListEntry
	Unk29          windows.Filetime
	SmartcardInfos binary.Pointer
}

type KiwiKerberosLogonSession10_1607 struct {
	UsageCount              uint32
	_                       uint32
	Unk0                    ntdll.ListEntry
	Unk1                    binary.Pointer
	Unk1b                   uint32
	_                       uint32
	Unk2                    windows.Filetime
	Unk4                    binary.Pointer
	Unk5                    binary.Pointer
	Unk6                    binary.Pointer
	LocallyUniqueIdentifier uint64
	Unk7                    windows.Filetime
	Unk8                    binary.Pointer
	Unk8b                   uint32
	_                       uint32
	Unk9                    windows.Filetime
	Unk11                   binary.Pointer
	Unk12                   binary.Pointer
	Unk13                   binary.Pointer
	_                       uint64
	Credentials             KiwiKerberosPrimaryCredential10_1607
	Unk14                   uint32
	Unk15                   uint32
	Unk16                   uint32
	Unk17                   uint32
	Unk18                   binary.Pointer
	Unk19                   binary.Pointer
	Unk20                   binary.Pointer
	Unk21                   binary.Pointer
	Unk22                   binary.Pointer
	Unk23                   binary.Pointer
	Unk24                   uint64
	Unk25                   uint64
	KeyList                 binary.Pointer
	Unk26                   binary.Pointer
	Tickets1                ntdll.ListEntry
	Unk27                   windows.Filetime
	Tickets2                ntdll.ListEntry
	Unk28                   windows.Filetime
	Tickets3                ntdll.ListEntry
	Unk29                   windows.Filetime
	SmartcardInfos          binary.Pointer
}

type KiwiKerberosPrimaryCredential10 struct {
	UserName ntdll.LsaUnicodeString
	Domain   ntdll.LsaUnicodeString
	Unk0     binary.Pointer
	Password ntdll.LsaUnicodeString
}

type KiwiKerberosPrimaryCredential10_1607 struct {
	UserName    ntdll.LsaUnicodeString
	Domain      ntdll.LsaUnicodeString
	UnkFunction binary.Pointer
	Type        uint32 // or flags 2 = normal, 1 = ISO
	_           uint32
	Password    ntdll.LsaUnicodeString
	IsoPassword KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO
}

type KIWI_KERBEROS_10_PRIMARY_CREDENTIAL_1607_ISO struct {
	StructSize uint32
	_          uint32
	IsoBlob    binary.Pointer // aligned;
}

type KerbExternalName struct {
	NameType  int16
	NameCount uint16
	_         uint32
	Names     []ntdll.LsaUnicodeString
}

type KiwiKerberosBuffer struct {
	Length uint32
	_      uint32
	Value  binary.Pointer
}

type KiwiKerberosInternalTicket51 struct {
	Flink               binary.Pointer
	Blink               binary.Pointer
	Unk0                binary.Pointer
	Unk1                binary.Pointer
	ServiceName         binary.Pointer
	TargetName          binary.Pointer
	DomainName          ntdll.LsaUnicodeString
	TargetDomainName    ntdll.LsaUnicodeString
	Description         ntdll.LsaUnicodeString
	AltTargetDomainName ntdll.LsaUnicodeString
	ClientName          binary.Pointer
	TicketFlags         uint32
	Unk2                uint32
	KeyType             uint32
	Key                 KiwiKerberosBuffer
	Unk3                binary.Pointer
	Unk4                binary.Pointer
	Unk5                binary.Pointer
	Unk6                binary.Pointer
	Unk7                binary.Pointer
	Unk8                binary.Pointer
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	RenewUntil          windows.Filetime
	Unk9                uint32
	Unk10               uint32
	Domain              binary.Pointer
	Unk11               uint32
	StrangeNames        binary.Pointer
	Unk12               uint32
	TicketEncType       uint32
	TicketKvno          uint32
	Ticket              KiwiKerberosBuffer
}

type KiwiKerberosInternalTicket52 struct {
	Flink               binary.Pointer
	Blink               binary.Pointer
	Unk0                binary.Pointer
	Unk1                binary.Pointer
	ServiceName         binary.Pointer
	TargetName          binary.Pointer
	DomainName          ntdll.LsaUnicodeString
	TargetDomainName    ntdll.LsaUnicodeString
	Description         ntdll.LsaUnicodeString
	AltTargetDomainName ntdll.LsaUnicodeString
	ClientName          binary.Pointer
	Name0               binary.Pointer
	TicketFlags         uint32
	Unk2                uint32
	KeyType             uint32
	Key                 KiwiKerberosBuffer
	Unk3                binary.Pointer
	Unk4                binary.Pointer
	Unk5                binary.Pointer
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	RenewUntil          windows.Filetime
	Unk6                uint32
	Unk7                uint32
	Domain              binary.Pointer
	Unk8                uint32
	StrangeNames        binary.Pointer
	Unk9                uint32
	TicketEncType       uint32
	TicketKvno          uint32
	Ticket              KiwiKerberosBuffer
}

type KiwiKerberosInternalTicket60 struct {
	Flink               binary.Pointer
	Blink               binary.Pointer
	Unk0                binary.Pointer
	Unk1                binary.Pointer
	ServiceName         binary.Pointer
	TargetName          binary.Pointer
	DomainName          ntdll.LsaUnicodeString
	TargetDomainName    ntdll.LsaUnicodeString
	Description         ntdll.LsaUnicodeString
	AltTargetDomainName ntdll.LsaUnicodeString
	ClientName          binary.Pointer
	Name0               binary.Pointer
	TicketFlags         uint32
	Unk2                uint32
	KeyType             uint32
	_                   uint32
	Key                 KiwiKerberosBuffer
	Unk3                binary.Pointer
	Unk4                binary.Pointer
	Unk5                binary.Pointer
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	RenewUntil          windows.Filetime
	Unk6                uint32
	Unk7                uint32
	Domain              binary.Pointer
	Unk8                uint32
	_                   uint32
	StrangeNames        binary.Pointer
	Unk9                uint32
	TicketEncType       uint32
	TicketKvno          uint32
	_                   uint32
	Ticket              KiwiKerberosBuffer
}

type KiwiKerberosInternalTicket6 struct {
	Flink               binary.Pointer
	Blink               binary.Pointer
	Unk0                binary.Pointer
	Unk1                binary.Pointer
	ServiceName         binary.Pointer
	TargetName          binary.Pointer
	DomainName          ntdll.LsaUnicodeString
	TargetDomainName    ntdll.LsaUnicodeString
	Description         ntdll.LsaUnicodeString
	AltTargetDomainName ntdll.LsaUnicodeString
	KDCServer           ntdll.LsaUnicodeString //?
	ClientName          binary.Pointer
	Name0               binary.Pointer
	TicketFlags         uint32
	Unk2                uint32
	KeyType             uint32
	_                   uint32
	Key                 KiwiKerberosBuffer
	Unk3                binary.Pointer
	Unk4                binary.Pointer
	Unk5                binary.Pointer
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	RenewUntil          windows.Filetime
	Unk6                uint32
	Unk7                uint32
	Domain              binary.Pointer
	Unk8                uint32
	_                   uint32
	StrangeNames        binary.Pointer
	Unk9                uint32
	TicketEncType       uint32
	TicketKvno          uint32
	_                   uint32
	Ticket              KiwiKerberosBuffer
}

type KiwiKerberosInternalTicket10 struct {
	Flink               binary.Pointer
	Blink               binary.Pointer
	Unk0                binary.Pointer
	Unk1                binary.Pointer
	ServiceName         binary.Pointer
	TargetName          binary.Pointer
	DomainName          ntdll.LsaUnicodeString
	TargetDomainName    ntdll.LsaUnicodeString
	Description         ntdll.LsaUnicodeString
	AltTargetDomainName ntdll.LsaUnicodeString
	KDCServer           ntdll.LsaUnicodeString //?
	Unk10586_d          ntdll.LsaUnicodeString //?
	ClientName          binary.Pointer
	Name0               binary.Pointer
	TicketFlags         uint32
	Unk2                uint32
	KeyType             uint32
	_                   uint32
	Key                 KiwiKerberosBuffer
	Unk3                binary.Pointer
	Unk4                binary.Pointer
	Unk5                binary.Pointer
	_                   uint64 `align:8`
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	RenewUntil          windows.Filetime
	Unk6                uint32
	Unk7                uint32
	Domain              binary.Pointer
	Unk8                uint32
	_                   uint32
	StrangeNames        binary.Pointer
	Unk9                uint32
	TicketEncType       uint32
	TicketKvno          uint32
	_                   uint32
	Ticket              KiwiKerberosBuffer
}

type KiwiKerberosInternalTicket10_1607 struct {
	Flink               binary.Pointer
	Blink               binary.Pointer
	Unk0                binary.Pointer
	Unk1                binary.Pointer
	ServiceName         binary.Pointer
	TargetName          binary.Pointer
	DomainName          ntdll.LsaUnicodeString
	TargetDomainName    ntdll.LsaUnicodeString
	Description         ntdll.LsaUnicodeString
	AltTargetDomainName ntdll.LsaUnicodeString
	KDCServer           ntdll.LsaUnicodeString //?
	Unk10586_d          ntdll.LsaUnicodeString //?
	ClientName          binary.Pointer
	Name0               binary.Pointer
	TicketFlags         uint32
	Unk2                uint32
	Unk14393_0          uint32
	KeyType             uint32
	_                   uint32
	Key                 KiwiKerberosBuffer
	Unk14393_1          binary.Pointer
	Unk3                binary.Pointer // ULONG		KeyType2;
	Unk4                binary.Pointer // KIWI_KERBEROS_BUFFER	Key2;
	Unk5                binary.Pointer // up
	StartTime           windows.Filetime
	EndTime             windows.Filetime
	RenewUntil          windows.Filetime
	Unk6                uint32
	Unk7                uint32
	Domain              binary.Pointer
	Unk8                uint32
	_                   uint32
	StrangeNames        binary.Pointer
	Unk9                uint32
	TicketEncType       uint32
	TicketKvno          uint32
	_                   uint32
	Ticket              KiwiKerberosBuffer
}
