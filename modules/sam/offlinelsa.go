//go:build windows
// +build windows

package sam

// From: https://github.com/gtworek/PSBits/blob/master/OfflineSAM/OfflineAddAdmin.c

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/ntsecapi"
	"github.com/vincd/savoir/windows/offlinelsa"
)

var SidNameUseMap = map[uint32]string{
	windows.SidTypeUser:           "SidTypeUser",
	windows.SidTypeGroup:          "SidTypeGroup",
	windows.SidTypeDomain:         "SidTypeDomain",
	windows.SidTypeAlias:          "SidTypeAlias",
	windows.SidTypeWellKnownGroup: "SidTypeWellKnownGroup",
	windows.SidTypeDeletedAccount: "SidTypeDeletedAccount",
	windows.SidTypeInvalid:        "SidTypeInvalid",
	windows.SidTypeUnknown:        "SidTypeUnknown",
	windows.SidTypeComputer:       "SidTypeComputer",
	windows.SidTypeLabel:          "SidTypeLabel",
}

func EnumerateAccountOffline(workingDir string) error {
	var offlineLsaPolicy offlinelsa.OfflineLsaHandle

	if err := offlinelsa.OpenPolicy(workingDir, &offlineLsaPolicy); err != nil {
		return fmt.Errorf("Cannot LsaOffline OpenPolicy in directory %s: %s", workingDir, err)
	}
	defer offlinelsa.Close(offlineLsaPolicy)

	lsaSidsBufferSize := uint64(128)
	lsaSidsBuffer := make([]ntsecapi.LsaEnumerationInformation, lsaSidsBufferSize)
	countOfSids := uint64(0)

	var lsaEnumContext ntsecapi.LsaEnumerationHandle
	if err := offlinelsa.EnumerateAccounts(offlineLsaPolicy, &lsaEnumContext, &lsaSidsBuffer, 0, &countOfSids); err != nil {
		return fmt.Errorf("Cannot LsaOffline EnumerateAccounts: %s", err)
	}

	fmt.Printf("Number of SIDs in offline SAM: %d\n", countOfSids)

	if countOfSids > lsaSidsBufferSize {
		var lsaEnumContext ntsecapi.LsaEnumerationHandle
		lsaSidsBuffer = make([]ntsecapi.LsaEnumerationInformation, countOfSids)
		if err := offlinelsa.EnumerateAccounts(offlineLsaPolicy, &lsaEnumContext, &lsaSidsBuffer, 0, &countOfSids); err != nil {
			return fmt.Errorf("Cannot LsaOffline EnumerateAccounts: %s", err)
		}
	}

	builtinAdministratorsSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("cannot create WellKnownSid WinBuiltinAdministratorsSid: %s", err)
	}

	fmt.Printf("BuiltinAdministrators SID: %s\n", builtinAdministratorsSid)

	builtinUsersSid, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return fmt.Errorf("cannot create WellKnownSid WinBuiltinUsersSid: %s", err)
	}

	fmt.Printf("BuiltinUsers SID: %s\n", builtinUsersSid)

	// var lsaRightSeDebugPrivilege offlinelsa.LsaUnicodeString
	// var adminIndex = 0
	// var userIndex = 0
	for _, lsaInfo := range lsaSidsBuffer[:countOfSids] {
		name := make([]uint16, 128)
		nameLen := uint32(128)
		domainName := make([]uint16, 128)
		domainNameLen := uint32(128)
		use := uint32(0)
		err := windows.LookupAccountSid(nil, lsaInfo.Sid, &name[0], &nameLen, &domainName[0], &domainNameLen, &use)
		if err != nil {
			fmt.Printf("cannot lookup sid %s: %s\n", lsaInfo.Sid, err)
			continue
		}

		sidNameUse, ok := SidNameUseMap[use]
		if !ok {
			sidNameUse = fmt.Sprintf("%d", use)
		}
		fmt.Printf("%s: %s / %s (%s)\n", lsaInfo.Sid, windows.UTF16ToString(domainName), windows.UTF16ToString(name), sidNameUse)

		countOfRights := uint64(0)
		lsaRights := make([]offlinelsa.LsaUnicodeString, 128)
		if err := offlinelsa.EnumerateAccountRights(offlineLsaPolicy, lsaInfo.Sid, &lsaRights, &countOfRights); err != nil {
			fmt.Printf("cannot enumerate account rights for %s: %s\n", lsaInfo.Sid, err)
			continue
		}

		fmt.Printf("  Number of rights assigned in offline SAM: %d\n", countOfRights)
		for _, lsaRight := range lsaRights[:countOfRights] {
			priv := windows.UTF16PtrToString(lsaRight.Buffer)
			fmt.Printf("  - %s %d %d\n", priv, lsaRight.Length, lsaRight.MaximumLength)
		}

		/*if windows.EqualSid(lsaInfo.Sid, builtinAdministratorsSid) {
			adminIndex = i
		}

		if windows.EqualSid(lsaInfo.Sid, builtinUsersSid) {
			userIndex = i
		}*/

		// Free lsaRightsBuffer ?
	}

	adminRightsLength := uint64(0)
	adminRights := make([]offlinelsa.LsaUnicodeString, 128)
	if err := offlinelsa.EnumerateAccountRights(offlineLsaPolicy, builtinAdministratorsSid, &adminRights, &adminRightsLength); err != nil {
		return fmt.Errorf("cannot enumerate account rights for %s: %s", builtinAdministratorsSid, err)
	}

	userRightsLength := uint64(0)
	userRights := make([]offlinelsa.LsaUnicodeString, 128)
	if err := offlinelsa.EnumerateAccountRights(offlineLsaPolicy, builtinAdministratorsSid, &userRights, &userRightsLength); err != nil {
		return fmt.Errorf("cannot enumerate account rights for %s: %s", builtinAdministratorsSid, err)
	}

	fmt.Printf("Admin rights:\n")
	for _, lsaRight := range adminRights[:adminRightsLength] {
		priv := windows.UTF16PtrToString(lsaRight.Buffer)
		fmt.Printf("  - %s\n", priv)

		if priv == "SeDebugPrivilege" {
			fmt.Printf("Update user rights with this privilege\n")
			userRights[userRightsLength] = lsaRight
			userRightsLength += 1
		}
	}

	if err := offlinelsa.AddAccountRights(offlineLsaPolicy, builtinUsersSid, &userRights[0], userRightsLength); err != nil {
		return fmt.Errorf("cannot update account rights for %s: %s", builtinUsersSid, err)
	}

	return nil
}
