package livessp

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/windows"
)

type LiveSSPEntry struct {
	AuthenticationId uint64 `json:"authentication_id"`
}

func ParseLiveSSP(l utils.MemoryReader) ([]*LiveSSPEntry, error) {
	// This module is not supported on old Windows version.
	// TODO: handle when a module is not supported
	if l.BuildNumber() < windows.BuildNumberWindows8 {
		return make([]*LiveSSPEntry, 0), nil
	}

	livesspEntryPtr, _, err := globals.FindStructurePointerFromSignature(l, "livessp.dll", livesspSignatures)
	if err != nil {
		return nil, err
	}

	entries := make([]*LiveSSPEntry, 0)
	ptr := *livesspEntryPtr
	for ptr > 0 {
		entry := &KiwiLivesspListEntry{}
		if err := l.ReadStructure(ptr, entry); err != nil {
			return nil, err
		}

		if entry.Flink == *livesspEntryPtr {
			break
		}

		livesspEntry := LiveSSPEntry{
			AuthenticationId: entry.LocallyUniqueIdentifier,
		}

		entries = append(entries, &livesspEntry)
		ptr = entry.Flink
	}

	return entries, nil
}
