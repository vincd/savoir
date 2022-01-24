package krb5

import (
	"encoding/base64"
	"encoding/hex"
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
	return k.DisplayTicket(false, false)
}

// Return a Rubeus style output: `LSA.DisplayTicket`
func (k *KRBCred) DisplayTicket(displayB64ticket bool, extractKerberoastHash bool) string {
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

	if displayB64ticket {
		encoded, err := k.Marshal()
		if err != nil {
			s += fmt.Sprintf("Base64EncodedTicket     : An error occured while encoded KRBCred: %s\n", err)
		} else {
			s += fmt.Sprintf("Base64EncodedTicket     :\n%s\n", base64.StdEncoding.EncodeToString(encoded))
		}
	}

	if extractKerberoastHash && k.Tickets[0].SName.NameString[0] != "krbtgt" {
		if keyType == crypto.RC4_HMAC {
			cipherText := hex.EncodeToString(k.Tickets[0].EncPart.Cipher)
			hash := fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%x$%x", int32(keyType), "USER", "DOMAIN", sname, cipherText[0:32], cipherText[32:])
			s += fmt.Sprintf("Kerberoast Hash          :  %s\n", hash)
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
		return fmt.Errorf("Cannot create kirbi file %s", err)
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
		return nil, fmt.Errorf("The kirbi file \"%s\" does not exists.", path)
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
