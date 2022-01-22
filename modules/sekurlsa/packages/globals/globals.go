package globals

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/windows/ntdll"
)

type KiwiGenericPrimaryCredential struct {
	UserName ntdll.LsaUnicodeString
	Domain   ntdll.LsaUnicodeString
	Password ntdll.LsaUnicodeString
}

type SavoirCredential struct {
	AuthenticationId uint64 `json:"-"`
	Username         string `json:"username"`
	Domain           string `json:"domain"`
	Password         string `json:"password"`
	PasswordRaw      []byte `json:"-"`
}

func (c SavoirCredential) IsServerAccount() bool {
	return strings.HasSuffix(c.Username, "$")
}

func (c SavoirCredential) String() string {
	s := ""
	s += fmt.Sprintf("    * Domain  : %s\n", c.Domain)
	s += fmt.Sprintf("    * Username: %s\n", c.Username)
	if len(c.Password) > 0 {
		s += fmt.Sprintf("    * Password: %s\n", c.Password)
	}
	if len(c.Password) == 0 && len(c.PasswordRaw) > 0 {
		s += fmt.Sprintf("    * PassRaw : %x\n", c.PasswordRaw)
	}

	return s
}

type SavoirKerberosTicket struct {
	Type                uint32    `json:"type"`
	ServiceName         []string  `json:"service_name"`
	ServiceNameType     int16     `json:"service_name_type"`
	DomainName          string    `json:"domain_name"`
	TargetName          []string  `json:"target_name"`
	TargetNameType      int16     `json:"target_name_type"`
	TargetDomainName    string    `json:"target_domain_name"`
	ClientName          []string  `json:"client_name"`
	ClientNameType      int16     `json:"client_name_type"`
	AltTargetDomainName string    `json:"alt_target_domain_name"`
	Description         string    `json:"description"`
	StartTime           time.Time `json:"start_time"`
	EndTime             time.Time `json:"end_time"`
	RenewUntil          time.Time `json:"renew_until"`
	TicketFlags         uint32    `json:"ticket_flag"`
	KeyType             uint32    `json:"key_type"`
	Key                 []byte    `json:"key"`
	TicketEncType       uint32    `json:"ticket_enc_type"`
	TicketKvno          uint32    `json:"ticket_kvno"`
	Ticket              []byte    `json:"ticket"`
}

func (t SavoirKerberosTicket) String() string {
	s := ""
	s += fmt.Sprintf("    * Start/End/MaxRenew: %s ; %s ; %s\n", t.StartTime, t.EndTime, t.RenewUntil)
	s += fmt.Sprintf("    * ServiceName (%02d)  : %s @ %s\n", t.ServiceNameType, t.ServiceName, t.DomainName)
	s += fmt.Sprintf("    * TargetName  (%02d)  : %s @ %s\n", t.TargetNameType, t.TargetName, t.TargetDomainName)
	s += fmt.Sprintf("    * ClientName  (%02d)  : %s @ %s", t.ClientNameType, t.ClientName, t.AltTargetDomainName)

	if len(t.Description) > 0 {
		s += fmt.Sprintf(" (%s)", t.Description)
	}
	s += "\n"
	s += fmt.Sprintf("    * Flags %08x    :\n", t.TicketFlags)
	s += fmt.Sprintf("    * Session Key       : 0x%08x - \n", t.KeyType)
	s += fmt.Sprintf("        %x\n", t.Key)
	s += fmt.Sprintf("    * Ticket            : 0x%08x - %s - kvno = %d\n", t.TicketEncType, "", t.TicketKvno)
	s += fmt.Sprintf("        %x\n", t.Ticket)

	return s
}

func (t SavoirKerberosTicket) ToKRBCred() (*krb5.KRBCred, error) {
	ticket := krb5.Ticket{
		TktVNO: krb5.PVNO,
		Realm:  t.DomainName,
		SName: krb5.PrincipalName{
			NameType:   2, // SRV_INST
			NameString: t.ServiceName,
		},
		EncPart: krb5.EncryptedData{
			EType:  int32(t.TicketEncType),
			KVNO:   int(t.TicketKvno),
			Cipher: t.Ticket,
		},
	}

	krbCredInfo := krb5.KrbCredInfo{
		Key: krb5.EncryptionKey{
			KeyType:  int32(t.KeyType),
			KeyValue: t.Key,
		},
		PRealm: t.AltTargetDomainName,
		PName: krb5.PrincipalName{
			NameType:   int32(t.ClientNameType),
			NameString: t.ClientName,
		},
		Flags:     krb5.NewKerberosFlagsFromUInt32(t.TicketFlags),
		StartTime: t.StartTime,
		EndTime:   t.EndTime,
		RenewTill: t.RenewUntil,
		SRealm:    t.DomainName,
		SName: krb5.PrincipalName{
			NameType:   int32(t.ServiceNameType),
			NameString: t.ServiceName,
		},
	}

	k := &krb5.KRBCred{
		PVNO:    krb5.PVNO,
		MsgType: krb5.KRB_CRED,
		Tickets: []krb5.Ticket{ticket},
		DecryptedEncPart: krb5.EncKrbCredPart{
			TicketInfo: []krb5.KrbCredInfo{krbCredInfo},
		},
	}

	return k, nil
}

func (t SavoirKerberosTicket) generateFilename() string {
	h := sha1.New()
	h.Write(t.Ticket)

	return strings.ReplaceAll(fmt.Sprintf("%s.kirbi", strings.Join([]string{
		t.DomainName,
		strings.Join(t.ClientName, "_"),
		strings.Join(t.ServiceName, "_"),
		hex.EncodeToString(h.Sum(nil))[:8],
	}, "_")), "..", "!")
}

func (t SavoirKerberosTicket) Dump() (string, error) {
	cred, err := t.ToKRBCred()
	if err != nil {
		return "", err
	}

	path := t.generateFilename()
	if err := cred.SaveToFile(path); err != nil {
		return "", err
	}

	return path, nil
}
