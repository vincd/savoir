package credman

import (
	"reflect"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows/ntdll"
)

func ParseCrendentialMananger(l utils.MemoryReader, credmanEntryPtr binary.Pointer) ([]globals.SavoirCredential, error) {
	lsasrvCredManEntries := make([]globals.SavoirCredential, 0)

	if credmanEntryPtr == 0 {
		return lsasrvCredManEntries, nil
	}

	reference, err := globals.FindSignature(credmanSignatures, l.ProcessorArchitecture(), l.BuildNumber())
	if err != nil {
		return nil, err
	}

	credmanList := &KiwiCredmanSetListEntry{}
	if l.ReadStructure(credmanEntryPtr, credmanList); err != nil {
		return nil, err
	}

	credmanListStarter := &KiwiCredmanListStarter{}
	if l.ReadStructure(credmanList.List1, credmanListStarter); err != nil {
		return nil, err
	}

	// Check if there is a list
	startOffset := binary.GetStructureFieldOffset(reflect.TypeOf(*credmanListStarter), "Start", l.ProcessorArchitecture().Isx64())
	if credmanList.List1+binary.Pointer(startOffset) == credmanListStarter.Start {
		return lsasrvCredManEntries, nil
	}

	currentEntryPtr := credmanListStarter.Start
	for currentEntryPtr > 0 {
		// The structure start before the entry pointer (Flink)
		ptr := currentEntryPtr.WithOffset(-1 * reference.Offsets[4])

		flink, err := l.ReadPointer(ptr.WithOffset(reference.Offsets[4]))
		if err != nil {
			return nil, err
		}

		if flink == credmanListStarter.Start {
			break
		}

		username, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[0]))
		if err != nil {
			return nil, err
		}

		domain, err := ntdll.GetLsaUnicodeStringValue(l, ptr.WithOffset(reference.Offsets[1]))
		if err != nil {
			return nil, err
		}

		credmanEntry := globals.SavoirCredential{
			Username: username,
			Domain:   domain,
		}

		encPasswordPtr, err := l.ReadPointer(ptr.WithOffset(reference.Offsets[2]))
		if err != nil {
			return nil, err
		}

		encPasswordLength, err := l.ReadUInt64(ptr.WithOffset(reference.Offsets[3]))
		if err != nil {
			return nil, err
		}

		if encPasswordPtr > 0 && encPasswordLength > 0 {
			credmanEntry.PasswordRaw = make([]byte, encPasswordLength)
			if err := l.ReadStructure(encPasswordPtr, credmanEntry.PasswordRaw); err != nil {
				return nil, err
			}
		}

		lsasrvCredManEntries = append(lsasrvCredManEntries, credmanEntry)

		currentEntryPtr = flink
	}

	return lsasrvCredManEntries, nil
}
