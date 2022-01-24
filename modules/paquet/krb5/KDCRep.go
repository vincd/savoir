package krb5

import (
	"fmt"
	"strings"
	"time"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.2
type ASRep struct {
	KDCRep
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.2
type TGSRep struct {
	KDCRep
}

type marshalKDCRep struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	PAData  []PAData      `asn1:"explicit,optional,tag:2"`
	CRealm  string        `asn1:"generalstring,explicit,tag:3"`
	CName   PrincipalName `asn1:"explicit,tag:4"`
	Ticket  asn1.RawValue `asn1:"explicit,tag:5"`
	EncPart EncryptedData `asn1:"explicit,tag:6"`
}

type KDCRep struct {
	PVNO             int
	MsgType          int
	PAData           []PAData
	CRealm           string
	CName            PrincipalName
	Ticket           Ticket
	EncPart          EncryptedData
	DecryptedEncPart EncKDCRepPart
}

type LastReq struct {
	LRType  int32     `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"generalized,explicit,tag:1"`
}

type EncKDCRepPart struct {
	Key           EncryptionKey  `asn1:"explicit,tag:0"`
	LastReqs      []LastReq      `asn1:"explicit,tag:1"`
	Nonce         int            `asn1:"explicit,tag:2"`
	KeyExpiration time.Time      `asn1:"generalized,explicit,optional,tag:3"`
	Flags         asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime      time.Time      `asn1:"generalized,explicit,tag:5"`
	StartTime     time.Time      `asn1:"generalized,explicit,optional,tag:6"`
	EndTime       time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill     time.Time      `asn1:"generalized,explicit,optional,tag:8"`
	SRealm        string         `asn1:"generalstring,explicit,tag:9"`
	SName         PrincipalName  `asn1:"explicit,tag:10"`
	CAddr         []HostAddress  `asn1:"explicit,optional,tag:11"`
	EncPAData     []PAData       `asn1:"explicit,optional,tag:12"`
}

func (k *EncKDCRepPart) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("The method EncKDCRepPart::Marshal is not implemented")
}

func (k *EncKDCRepPart) Unarshal(b []byte) error {
	return fmt.Errorf("The method EncKDCRepPart::Unarshal is not implemented")
}

func (k *EncKDCRepPart) KrbCredInfo() KrbCredInfo {
	return KrbCredInfo{
		Key:       k.Key,
		Flags:     k.Flags,
		AuthTime:  k.AuthTime,
		StartTime: k.StartTime,
		EndTime:   k.EndTime,
		RenewTill: k.RenewTill,
		SRealm:    k.SRealm,
		SName:     k.SName,
	}
}

func (k *ASRep) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("The method ASRep::Marshal is not implemented")
}

func (k *ASRep) Unmarshal(b []byte) error {
	m := &marshalKDCRep{}
	if err := unmarshalMessage(b, m, KRB_AS_REP); err != nil {
		return err
	}

	if err := k.Ticket.Unmarshal(m.Ticket.Bytes); err != nil {
		return err
	}

	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.CRealm = m.CRealm
	k.CName = m.CName
	k.EncPart = m.EncPart

	return nil
}

func (k *ASRep) DecryptAsRepPart(key []byte) error {
	// The key usage value for encrypting this field is 3 in an AS-REP
	// message, using the client's long-term key or another key selected
	// via pre-authentication mechanisms.
	decAsRepPart, err := k.EncPart.Decrypt(key, 3)
	if err != nil {
		return err
	}

	// We have a EncASRepPart on an ASRep
	return unmarshalMessage(decAsRepPart, &k.DecryptedEncPart, TagEncASRepPart)
}

func (k *ASRep) GetAuthenticator() (*Authenticator, error) {
	auth, err := NewAuthenticator(k.CRealm, k.CName)
	if err != nil {
		return nil, err
	}

	return auth, nil
}

func (k *ASRep) GetEncryptedAuthenticator(usage uint32) (*EncryptedData, error) {
	auth, err := k.GetAuthenticator()
	if err != nil {
		return nil, err
	}

	encryptedAuthenticator, err := auth.Encrypt(k.DecryptedEncPart.Key, usage)
	if err != nil {
		return nil, err
	}

	return encryptedAuthenticator, nil
}

func (k *ASRep) JohnString() string {
	return fmt.Sprintf("$krb5asrep$%s@%s:%x$%x", k.KDCRep.CName.NameString[0], k.KDCRep.CRealm, k.KDCRep.EncPart.Cipher[0:16], k.KDCRep.EncPart.Cipher[16:])
}

func (k *ASRep) HashcatString() string {
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%x$%x", k.KDCRep.EncPart.EType, k.KDCRep.CName.NameString[0], k.KDCRep.CRealm, k.KDCRep.EncPart.Cipher[0:16], k.KDCRep.EncPart.Cipher[16:])
}

func (k *KDCRep) Credentials() *KRBCred {
	info := k.DecryptedEncPart.KrbCredInfo()
	info.PRealm = k.CRealm
	info.PName = k.CName

	cred := &KRBCred{
		PVNO:    PVNO,
		MsgType: KRB_CRED,
		Tickets: []Ticket{k.Ticket},
		DecryptedEncPart: EncKrbCredPart{
			TicketInfo: []KrbCredInfo{info},
		},
	}

	return cred
}

func (k *TGSRep) Marshal() ([]byte, error) {
	return nil, fmt.Errorf("The method TGSRep::Marshal is not implemented")
}

func (k *TGSRep) Unmarshal(b []byte) error {
	m := &marshalKDCRep{}
	if err := unmarshalMessage(b, m, KRB_TGS_REP); err != nil {
		return err
	}

	if err := k.Ticket.Unmarshal(m.Ticket.Bytes); err != nil {
		return err
	}

	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.CRealm = m.CRealm
	k.CName = m.CName
	k.EncPart = m.EncPart

	return nil
}

func (k *TGSRep) DecryptTgsRepPart(key []byte) error {
	// In a TGS-REP message, the key
	// usage value is 8 if the TGS session key is used, or 9 if a TGS
	// authenticator subkey is used.
	// TODO: check if TGS use session key or authenticator subkey
	decTgsPart, err := k.EncPart.Decrypt(key, 8)
	if err != nil {
		return err
	}

	// We have a EncASRepPart on an ASRep
	return unmarshalMessage(decTgsPart, &k.DecryptedEncPart, TagEncTGSRepPart)
}

func (k *TGSRep) HashString(username string, spn string) string {
	eType := k.Ticket.EncPart.EType
	cipher := k.Ticket.EncPart.Cipher
	realm := k.Ticket.Realm
	spn = strings.ReplaceAll(spn, ":", "~")

	if eType == crypto.RC4_HMAC {
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%x$%x", eType, username, realm, spn, cipher[0:16], cipher[16:])
	} else if eType == crypto.AES128_CTS_HMAC_SHA1_96 {
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%x$%x", eType, username, realm, spn, cipher[len(cipher)-12:], cipher[:len(cipher)-12])
	} else if eType == crypto.AES256_CTS_HMAC_SHA1_96 {
		return fmt.Sprintf("$krb5tgs$%d$%s$%s$*%s*$%x$%x", eType, username, realm, spn, cipher[len(cipher)-12:], cipher[:len(cipher)-12])
	} else if eType == crypto.DES_CBC_MD5 {
		return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%x$%x", eType, username, realm, spn, cipher[0:16], cipher[16:])
	} else {
		return fmt.Sprintf("The cipher \"%s\" is not supported.", crypto.ETypeToString(eType))
	}
}
