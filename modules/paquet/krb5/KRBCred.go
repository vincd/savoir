package krb5

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.8
// https://datatracker.ietf.org/doc/html/rfc4120#section-5.8.1
type marshalKRBCred struct {
	PVNO    int                  `asn1:"explicit,tag:0"`
	MsgType int                  `asn1:"explicit,tag:1"`
	Tickets SequenceOfRawTickets `asn1:"explicit,tag:2"`
	EncPart EncryptedData        `asn1:"explicit,tag:3"`
}

type KRBCred struct {
	PVNO             int
	MsgType          int
	Tickets          []Ticket
	EncPart          EncryptedData
	DecryptedEncPart EncKrbCredPart
}

type KrbCredInfo struct {
	Key       EncryptionKey  `asn1:"explicit,tag:0"`
	PRealm    string         `asn1:"generalstring,optional,explicit,tag:1"`
	PName     PrincipalName  `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time      `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time      `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string         `asn1:"optional,explicit,ia5,tag:8"`
	SName     PrincipalName  `asn1:"optional,explicit,tag:9"`
	CAddr     HostAddresses  `asn1:"optional,explicit,tag:10"`
}

type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo `asn1:"explicit,tag:0"`
	Nouce      int           `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int           `asn1:"optional,explicit,tag:3"`
	SAddress   HostAddress   `asn1:"optional,explicit,tag:4"`
	RAddress   HostAddress   `asn1:"optional,explicit,tag:5"`
}

func (k *KRBCred) String() string {
	return k.DisplayTicket(false, false, nil)
}

// Return a Rubeus style output: `LSA.DisplayTicket`
//  * displayB64ticket: display the ticket encoded as base64
//  * nowrap: don't wrap the base64 ticket output
//  * serviceKey: key to decrypt PAC informations
func (k *KRBCred) DisplayTicket(displayB64ticket bool, nowrap bool, serviceKey []byte) string {
	if k.DecryptedEncPart.TicketInfo == nil || len(k.DecryptedEncPart.TicketInfo) == 0 {
		return "[!] Credential is empty."
	}

	sname := strings.Join(k.Tickets[0].SName.NameString, "/")
	keyType := k.DecryptedEncPart.TicketInfo[0].Key.KeyType

	s := ""
	s += fmt.Sprintf("ServiceName              :  %s\n", sname)
	s += fmt.Sprintf("ServiceRealm             :  %s\n", k.DecryptedEncPart.TicketInfo[0].SRealm)
	s += fmt.Sprintf("UserName                 :  %s\n", strings.Join(k.DecryptedEncPart.TicketInfo[0].PName.NameString, "@"))
	s += fmt.Sprintf("UserRealm                :  %s\n", k.DecryptedEncPart.TicketInfo[0].PRealm)
	s += fmt.Sprintf("StartTime                :  %s\n", k.DecryptedEncPart.TicketInfo[0].StartTime)
	s += fmt.Sprintf("EndTime                  :  %s\n", k.DecryptedEncPart.TicketInfo[0].EndTime)
	s += fmt.Sprintf("RenewTill                :  %s\n", k.DecryptedEncPart.TicketInfo[0].RenewTill)
	s += fmt.Sprintf("Flags                    :  %s\n", strings.Join(ParseTicketFlags(k.DecryptedEncPart.TicketInfo[0].Flags), " ; "))
	s += fmt.Sprintf("KeyType                  :  %s\n", crypto.ETypeToString(keyType))
	s += fmt.Sprintf("Base64(key)              :  %s\n", base64.StdEncoding.EncodeToString(k.DecryptedEncPart.TicketInfo[0].Key.KeyValue))

	// TODO: asrepKey

	if displayB64ticket {
		b64, err := k.Base64()
		if err != nil {
			s += fmt.Sprintf("Base64EncodedTicket      : An error occured while encoded KRBCred: %s\n", err)
		} else {
			if nowrap {
				s += fmt.Sprintf("Base64EncodedTicket      :\n%s\n", b64)
			} else {
				s += "Base64EncodedTicket      :\n"

				for i := 0; i < len(b64); i += 100 {
					if i+100 > len(b64) {
						s += fmt.Sprintf("  %s\n", b64[i:len(b64)-1])
					} else {
						s += fmt.Sprintf("  %s\n", b64[i:i+100])
					}
				}
			}
		}
	}

	if len(serviceKey) > 0 {
		if err := k.Tickets[0].Decrypt(serviceKey, KeyUsageAsRepTgsRepTicket); err != nil {
			s += fmt.Sprintf("[!] Error decoding PAC: %s", err)
		} else {
			pacType, err := k.Tickets[0].GetPacType()
			if err != nil {
				s += fmt.Sprintf("[!] Error getting PacType: %s", err)
			} else {
				s += "Decrypted PAC                  :\n"

				if pacType.ValidationInfo != nil {
					groups := make([]string, 0)
					for _, groupId := range pacType.ValidationInfo.GroupIDs {
						groups = append(groups, fmt.Sprintf("%d", groupId.RelativeID))
					}

					extraSids := make([]string, 0)
					for _, extraSid := range pacType.ValidationInfo.ExtraSIDs {
						extraSids = append(extraSids, extraSid.SID.String())
					}

					resourceGroupIDs := make([]string, 0)
					for _, resourceGroupID := range pacType.ValidationInfo.ResourceGroupIDs {
						resourceGroupIDs = append(resourceGroupIDs, fmt.Sprintf("%d", resourceGroupID.RelativeID))
					}

					s += "  Logon Info                   :\n"
					s += fmt.Sprintf("    LogOnTime                  : %s\n", pacType.ValidationInfo.LogOnTime.Time())
					s += fmt.Sprintf("    LogOffTime                 : %s\n", pacType.ValidationInfo.LogOffTime.Time())
					s += fmt.Sprintf("    KickOffTime                : %s\n", pacType.ValidationInfo.KickOffTime.Time())
					s += fmt.Sprintf("    PasswordLastSet            : %s\n", pacType.ValidationInfo.PasswordLastSet.Time())
					s += fmt.Sprintf("    PasswordCanChange          : %s\n", pacType.ValidationInfo.PasswordCanChange.Time())
					s += fmt.Sprintf("    PasswordMustChange         : %s\n", pacType.ValidationInfo.PasswordMustChange.Time())
					s += fmt.Sprintf("    EffectiveName              : %s\n", pacType.ValidationInfo.EffectiveName.Value)
					s += fmt.Sprintf("    FullName                   : %s\n", pacType.ValidationInfo.FullName.Value)
					s += fmt.Sprintf("    LogonScript                : %s\n", pacType.ValidationInfo.LogonScript.Value)
					s += fmt.Sprintf("    ProfilePath                : %s\n", pacType.ValidationInfo.ProfilePath.Value)
					s += fmt.Sprintf("    HomeDirectory              : %s\n", pacType.ValidationInfo.HomeDirectory.Value)
					s += fmt.Sprintf("    HomeDirectoryDrive         : %s\n", pacType.ValidationInfo.HomeDirectoryDrive.Value)
					s += fmt.Sprintf("    LogonCount                 : %d\n", pacType.ValidationInfo.LogonCount)
					s += fmt.Sprintf("    BadPasswordCount           : %d\n", pacType.ValidationInfo.BadPasswordCount)
					s += fmt.Sprintf("    UserID                     : %d\n", pacType.ValidationInfo.UserID)
					s += fmt.Sprintf("    PrimaryGroupID             : %d\n", pacType.ValidationInfo.PrimaryGroupID)
					s += fmt.Sprintf("    GroupCount                 : %d\n", pacType.ValidationInfo.GroupCount)
					s += fmt.Sprintf("    Groups                     : %s\n", strings.Join(groups, ", "))
					s += fmt.Sprintf("    UserFlags                  : %d\n", pacType.ValidationInfo.UserFlags)
					s += fmt.Sprintf("    UserSessionKey             : %x\n", pacType.ValidationInfo.UserSessionKey.CypherBlock[0].Data)
					s += fmt.Sprintf("    LogonServer                : %s\n", pacType.ValidationInfo.LogonServer.Value)
					s += fmt.Sprintf("    LogonDomainName            : %s\n", pacType.ValidationInfo.LogonDomainName.Value)
					s += fmt.Sprintf("    LogonDomainID              : %s\n", pacType.ValidationInfo.LogonDomainID.String())
					s += fmt.Sprintf("    UserAccountControl         : %d\n", pacType.ValidationInfo.UserAccountControl)
					s += fmt.Sprintf("    SubAuthStatus              : %d\n", pacType.ValidationInfo.SubAuthStatus)
					s += fmt.Sprintf("    LastSuccessfulILogon       : %s\n", pacType.ValidationInfo.LastSuccessfulILogon.Time())
					s += fmt.Sprintf("    LastFailedILogon           : %s\n", pacType.ValidationInfo.LastFailedILogon.Time())
					s += fmt.Sprintf("    FailedILogonCount          : %d\n", pacType.ValidationInfo.FailedILogonCount)
					s += fmt.Sprintf("    SIDCount                   : %d\n", pacType.ValidationInfo.SIDCount)
					s += fmt.Sprintf("    ExtraSIDs                  : %s\n", strings.Join(extraSids, ", "))
					s += fmt.Sprintf("    ResourceGroupDomainSID     : %s\n", pacType.ValidationInfo.ResourceGroupDomainSID.String())
					s += fmt.Sprintf("    ResourceGroupCount         : %d\n", pacType.ValidationInfo.ResourceGroupCount)
					s += fmt.Sprintf("    ResourceGroupIDs           : %s\n", strings.Join(resourceGroupIDs, ", "))
				}

				if pacType.ClientInfo != nil {
					s += "  ClientName                   :\n"
					s += fmt.Sprintf("    Client Id                  : %s\n", pacType.ClientInfo.ClientId.Time())
					s += fmt.Sprintf("    Client Name                : %s\n", pacType.ClientInfo.Name)
				}

				if pacType.UpnDnsInfo != nil {
					s += "  UpnDns                       :\n"
					s += fmt.Sprintf("    DNS Domain Name            : %s\n", pacType.UpnDnsInfo.DNSDomainName)
					s += fmt.Sprintf("    IUPN                       : %s\n", pacType.UpnDnsInfo.UPN)
					s += fmt.Sprintf("    Flags                      : 0x%x\n", pacType.UpnDnsInfo.Flags)
				}

				// TODO: check PAC signatures
			}
		}
	}

	return s
}

// Unmarshal the byte to the KRBCred structure and decrypt the encrypted part.
func (k *KRBCred) Unmarshal(b []byte) error {
	m := &marshalKRBCred{}
	if err := unmarshalMessage(b, m, TagKRBCred); err != nil {
		return err
	}

	tickets, err := m.Tickets.Tickets()
	if err != nil {
		return err
	}

	decPart, err := m.EncPart.Decrypt(nil, 0)
	if err != nil {
		return nil
	}

	if err := k.DecryptedEncPart.Unmarshal(decPart); err != nil {
		return err
	}

	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.EncPart = m.EncPart
	k.Tickets = tickets

	return nil
}

func (k *KRBCred) Marshal() ([]byte, error) {
	m := marshalKRBCred{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
	}

	if err := m.Tickets.AddTickets(k.Tickets); err != nil {
		return nil, err
	}

	marshledDecryptedPart, err := k.DecryptedEncPart.Marshal()
	if err != nil {
		return nil, err
	}

	if err := m.EncPart.Encrypt(0, nil, marshledDecryptedPart, 0); err != nil {
		return nil, err
	}

	return asn1.MarshalWithParams(m, fmt.Sprintf("application,explicit,tag:%d", TagKRBCred))
}

// Save to KRBCred to a kirbi file
func (k *KRBCred) SaveToFile(path string) error {
	kirbi, err := k.Marshal()
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create kirbi file %s", err)
	}
	defer f.Close()

	f.Write(kirbi)

	return nil
}

// Encode to base64 a KRBCred structure. Usefull when you want to share a ticket
// with other tools such as Rubeus.
func (k *KRBCred) Base64() (string, error) {
	kirbi, err := k.Marshal()
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(kirbi), nil
}

func NewKrbCredFromFile(path string) (*KRBCred, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("kirbi file \"%s\" does not exists", path)
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	kirbi := &KRBCred{}
	if err := kirbi.Unmarshal(buf); err != nil {
		return nil, err
	}

	return kirbi, nil
}

func NewKrbCredFromBase64(kirbi64 string) (*KRBCred, error) {
	buf, err := base64.StdEncoding.DecodeString(kirbi64)
	if err != nil {
		return nil, err
	}

	kirbi := &KRBCred{}
	if err := kirbi.Unmarshal(buf); err != nil {
		return nil, err
	}

	return kirbi, nil
}

func (k *EncKrbCredPart) Marshal() ([]byte, error) {
	return asn1.MarshalWithParams(*k, fmt.Sprintf("application,explicit,tag:%d", TagEncKrbCredPart))
}

func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%d", TagEncKrbCredPart))
	return err
}
