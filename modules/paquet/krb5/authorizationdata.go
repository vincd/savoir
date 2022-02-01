package krb5

import (
	"fmt"

	"github.com/vincd/savoir/modules/paquet/pac"
	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.6
type AuthorizationDataEntry struct {
	ADType int32  `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

type AuthorizationData []AuthorizationDataEntry

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.6.1
type ADIfRelevant AuthorizationData

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.4
const (
	AuthorizationDataIfRelevant                  int32 = 1
	AuthorizationDataIntendedForServer           int32 = 2
	AuthorizationDataIntendedForApplicationClass int32 = 3
	AuthorizationDataKdcIssued                   int32 = 4
	AuthorizationDataAndOr                       int32 = 5
	AuthorizationDataMandatoryTicketExtesions    int32 = 6
	AuthorizationDataInTicketExtensions          int32 = 7
	AuthorizationDataMandatoryForKdc             int32 = 8
	AuthorizationDataOsfDce                      int32 = 64
	AuthorizationDataSesame                      int32 = 65
	AuthorizationDataAdOsfDcePkiCertid           int32 = 66
	AuthorizationDataWin2kPac                    int32 = 128
	AuthorizationDataEtypeNegotiation            int32 = 129
)

// Filter AuthorizationData on ADType
func (a *AuthorizationData) GetADEntriesFromType(adType int32) []AuthorizationDataEntry {
	entries := make([]AuthorizationDataEntry, 0)
	for _, ad := range *a {
		entries = append(entries, ad)
	}

	return entries
}

func (a *AuthorizationData) GetIfRelevant() (*AuthorizationData, error) {
	entries := a.GetADEntriesFromType(AuthorizationDataIfRelevant)
	if len(entries) != 1 {
		return nil, fmt.Errorf("invalid IfRelevant entry in authorization data (%d)", len(entries))
	}

	ad := &AuthorizationData{}
	if _, err := asn1.Unmarshal(entries[0].ADData, ad); err != nil {
		return nil, fmt.Errorf("cannot unmarshal IfRelevant: %s", err)
	}

	return ad, nil
}

// Get Win2kPac PacType
func (a *AuthorizationData) GetWin2kPac() (*pac.PacType, error) {
	entries := a.GetADEntriesFromType(AuthorizationDataWin2kPac)
	if len(entries) != 1 {
		return nil, fmt.Errorf("invalid Win2kPac entry in authorization data (%d)", len(entries))
	}

	pacType, err := pac.NewPacType(entries[0].ADData)
	if err != nil {
		return nil, fmt.Errorf("cannot parse PacType: %s", err)
	}

	return pacType, nil
}
