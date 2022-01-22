package ssp

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
)

func ParseSSP(l utils.MemoryReader) ([]*globals.SavoirCredential, error) {
	sspEntryPtr, _, err := globals.FindStructurePointerFromSignature(l, "msv1_0.dll", sspSignatures)
	if err != nil {
		return nil, err
	}

	entries := make([]*globals.SavoirCredential, 0)
	ptr := *sspEntryPtr
	for ptr > 0 {
		entry := &KiwiSSPCredentialListEntry{}
		if err := l.ReadStructure(ptr, entry); err != nil {
			return nil, err
		}

		if entry.Flink == *sspEntryPtr {
			break
		}

		username, err := entry.Credentials.UserName.ReadString(l)
		if err != nil {
			return nil, err
		}

		domain, err := entry.Credentials.Domain.ReadString(l)
		if err != nil {
			return nil, err
		}

		passwordRaw, err := entry.Credentials.Password.ReadBytes(l)
		if err != nil {
			return nil, err
		}

		sspEntry := &globals.SavoirCredential{
			AuthenticationId: entry.LogonId,
			Username:         username,
			Domain:           domain,
			PasswordRaw:      passwordRaw,
		}

		entries = append(entries, sspEntry)
		ptr = entry.Flink
	}

	return entries, nil
}
