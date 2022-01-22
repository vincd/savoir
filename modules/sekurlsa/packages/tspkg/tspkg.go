package tspkg

import (
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/windows/ntddk"
)

func ParseTsPkg(l utils.MemoryReader) ([]*globals.SavoirCredential, error) {
	rtlAVLTable := &ntddk.RtlAvlTable{}
	reference, err := globals.FindStructureFromSignature(l, "tspkg.dll", tspkgSignatures, rtlAVLTable)
	if err != nil {
		return nil, err
	}

	ptrList, err := rtlAVLTable.Walk(l)
	if err != nil {
		return nil, err
	}

	entries := make([]*globals.SavoirCredential, 0)
	for _, ptr := range ptrList {
		authenticationId, err := l.ReadUInt64(ptr.WithOffset(reference.Offsets[1]))
		if err != nil {
			return nil, err
		}

		primaryCredentialPtr, err := l.ReadPointer(ptr.WithOffset(reference.Offsets[2]))
		if err != nil {
			return nil, err
		}

		if primaryCredentialPtr != 0 {
			primaryCredentials := &KiwiTsPrimaryCredential{}
			if err := l.ReadStructure(primaryCredentialPtr, primaryCredentials); err != nil {
				return nil, err
			}

			username, err := primaryCredentials.Credentials.UserName.ReadString(l)
			if err != nil {
				return nil, err
			}

			domain, err := primaryCredentials.Credentials.Domain.ReadString(l)
			if err != nil {
				return nil, err
			}

			passwordRaw, err := primaryCredentials.Credentials.Password.ReadBytes(l)
			if err != nil {
				return nil, err
			}

			// Switch Username and Domain ¯\_(ツ)_/¯
			// https://github.com/skelsec/pypykatz/blob/dd129ff36e00593d1340776b517f7e749ad8d314/pypykatz/lsadecryptor/packages/tspkg/decryptor.py#L80
			entries = append(entries, &globals.SavoirCredential{
				AuthenticationId: authenticationId,
				Username:         domain,
				Domain:           username,
				PasswordRaw:      passwordRaw,
			})
		}
	}

	return entries, nil
}
