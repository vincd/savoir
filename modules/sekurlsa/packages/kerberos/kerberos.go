package kerberos

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows/ntddk"
	"github.com/vincd/savoir/windows/ntdll"
)

type KerberosEntry struct {
	Credential *globals.SavoirCredential
	Tickets    []*globals.SavoirKerberosTicket
}

func readKerbExternalNamePointer(l utils.MemoryReader, ptr binary.Pointer) (*KerbExternalName, error) {
	externalNamePtr, err := l.ReadPointer(ptr)
	if err != nil {
		return nil, err
	}

	nameType, err := utils.MemoryReaderUInt16(l, externalNamePtr)
	if err != nil {
		return nil, err
	}

	nameCount, err := utils.MemoryReaderUInt16(l, externalNamePtr.WithOffset(2))
	if err != nil {
		return nil, err
	}

	names := make([]ntdll.LsaUnicodeString, 0)
	if l.ProcessorArchitecture().Isx64() {
		externalNamePtr = externalNamePtr.WithOffset(8)
	} else {
		externalNamePtr = externalNamePtr.WithOffset(4)
	}

	nameSize := int64(binary.Size(ntdll.LsaUnicodeString{}, l.ProcessorArchitecture().Isx64()))
	for i := uint16(0); i < nameCount; i++ {
		name := ntdll.LsaUnicodeString{}
		if err := l.ReadStructure(externalNamePtr, &name); err != nil {
			return nil, err
		}

		names = append(names, name)
		externalNamePtr = externalNamePtr.WithOffset(nameSize)
	}

	externalName := &KerbExternalName{
		NameType:  int16(nameType),
		NameCount: nameCount,
		Names:     names,
	}

	return externalName, nil
}

func readExternalNames(l utils.MemoryReader, externalNames *KerbExternalName) ([]string, error) {
	names := make([]string, 0)

	for _, lsaName := range externalNames.Names {
		name, err := lsaName.ReadString(l)
		if err != nil {
			return nil, err
		}

		names = append(names, name)
	}

	return names, nil
}

func readKerberosBuffer(l utils.MemoryReader, ptr binary.Pointer) ([]byte, error) {
	kerbBuffer := &KiwiKerberosBuffer{}
	if err := l.ReadStructure(ptr, kerbBuffer); err != nil {
		return nil, err
	}

	value, err := l.Read(kerbBuffer.Value, kerbBuffer.Length)
	if err != nil {
		return nil, err
	}

	return value, nil
}

func parseKerberosTicket(l utils.MemoryReader, reference *globals.Signature, ptr binary.Pointer, group int) (*globals.SavoirKerberosTicket, error) {
	// utils.DumpMemory(l, ptr, 512)

	startTime, err := l.ReadFileTime(ptr.WithOffset(reference.Offsets[14]))
	if err != nil {
		return nil, err
	}

	endTime, err := l.ReadFileTime(ptr.WithOffset(reference.Offsets[15]))
	if err != nil {
		return nil, err
	}

	renewUntil, err := l.ReadFileTime(ptr.WithOffset(reference.Offsets[16]))
	if err != nil {
		return nil, err
	}

	serviceName, err := readKerbExternalNamePointer(l, ptr.WithOffset(reference.Offsets[11]))
	if err != nil {
		return nil, err
	}

	serviceNames, err := readExternalNames(l, serviceName)
	if err != nil {
		return nil, err
	}

	clientName, err := readKerbExternalNamePointer(l, ptr.WithOffset(reference.Offsets[12]))
	if err != nil {
		return nil, err
	}

	clientNames, err := readExternalNames(l, clientName)
	if err != nil {
		return nil, err
	}

	targetName, err := readKerbExternalNamePointer(l, ptr.WithOffset(reference.Offsets[13]))
	if err != nil {
		return nil, err
	}

	targetNames, err := readExternalNames(l, targetName)
	if err != nil {
		return nil, err
	}

	domainName, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[17]))
	if err != nil {
		return nil, err
	}

	targetDomainName, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[18]))
	if err != nil {
		return nil, err
	}

	altTargetDomainName, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[19]))
	if err != nil {
		return nil, err
	}

	description, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[20]))
	if err != nil {
		return nil, err
	}

	ticketFlags, err := l.ReadUInt32(ptr.WithOffset(reference.Offsets[21]))
	if err != nil {
		return nil, err
	}

	keyType, err := l.ReadUInt32(ptr.WithOffset(reference.Offsets[22]))
	if err != nil {
		return nil, err
	}

	keyValue, err := readKerberosBuffer(l, ptr.WithOffset(reference.Offsets[23]))
	if err != nil {
		return nil, err
	}

	ticketEncType, err := l.ReadUInt32(ptr.WithOffset(reference.Offsets[24]))
	if err != nil {
		return nil, err
	}

	ticketKvno, err := l.ReadUInt32(ptr.WithOffset(reference.Offsets[25]))
	if err != nil {
		return nil, err
	}

	ticketValue, err := readKerberosBuffer(l, ptr.WithOffset(reference.Offsets[26]))
	if err != nil {
		return nil, err
	}

	tk := &globals.SavoirKerberosTicket{
		ServiceNameType:     serviceName.NameType,
		ServiceName:         serviceNames,
		DomainName:          domainName,
		TargetNameType:      targetName.NameType,
		TargetName:          targetNames,
		TargetDomainName:    targetDomainName,
		ClientNameType:      clientName.NameType,
		ClientName:          clientNames,
		AltTargetDomainName: altTargetDomainName,
		Description:         description,
		StartTime:           startTime,
		EndTime:             endTime,
		RenewUntil:          renewUntil,
		TicketFlags:         ticketFlags,
		KeyType:             keyType,
		Key:                 keyValue,
		TicketEncType:       ticketEncType,
		TicketKvno:          ticketKvno,
		Ticket:              ticketValue,
	}

	return tk, nil
}

func ParseKerberosTickets(l utils.MemoryReader, reference *globals.Signature, ptr binary.Pointer, group int) ([]*globals.SavoirKerberosTicket, error) {
	firstEntryPtr, err := l.ReadPointer(ptr)
	if err != nil {
		return nil, err
	}

	entryPtr := firstEntryPtr

	i := 0
	tickets := make([]*globals.SavoirKerberosTicket, 0)
	for entryPtr > 0 {
		flink, err := l.ReadPointer(entryPtr)
		if err != nil {
			return nil, err
		}

		// Stop if the next entry point to the current entry
		if flink == entryPtr || flink == firstEntryPtr {
			break
		}

		ticket, err := parseKerberosTicket(l, reference, entryPtr, group)
		if err != nil {
			return nil, err
		}

		tickets = append(tickets, ticket)

		if flink == firstEntryPtr {
			break
		}

		entryPtr = flink
		i++
	}

	return tickets, nil
}

func ParseKerberos(l utils.MemoryReader) ([]*KerberosEntry, error) {
	rtlAVLTable := &ntddk.RtlAvlTable{}
	reference, err := globals.FindStructureFromSignature(l, "kerberos.dll", kerberosSignatures, rtlAVLTable)
	if err != nil {
		return nil, err
	}

	ptrList, err := rtlAVLTable.Walk(l)
	if err != nil {
		return nil, err
	}

	entries := make([]*KerberosEntry, 0)
	for _, ptr := range ptrList {
		authenticationId, err := l.ReadUInt64(ptr.WithOffset(reference.Offsets[3]))
		if err != nil {
			return nil, err
		}

		username, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[2]+reference.Offsets[4]))
		if err != nil {
			return nil, err
		}

		domain, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[2]+reference.Offsets[5]))
		if err != nil {
			return nil, err
		}

		passwordRaw, err := ntdll.GetLsaUnicodeBytesValue(l, ptr.WithOffset(reference.Offsets[2]+reference.Offsets[6]))
		if err != nil {
			return nil, err
		}

		entry := &KerberosEntry{
			Credential: &globals.SavoirCredential{
				AuthenticationId: authenticationId,
				Username:         username,
				Domain:           domain,
				PasswordRaw:      passwordRaw,
			},
			Tickets: make([]*globals.SavoirKerberosTicket, 0),
		}

		for i := 0; i < 3; i++ {
			tickets, err := ParseKerberosTickets(l, reference, ptr.WithOffset(reference.Offsets[7+i]), i)
			if err != nil {
				return nil, err
			}

			entry.Tickets = append(entry.Tickets, tickets...)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}
