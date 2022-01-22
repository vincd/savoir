package krb5

import (
	"fmt"
	"time"

	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.5.1
type marshalAPReq struct {
	PVNO                   int            `asn1:"explicit,tag:0"`
	MsgType                int            `asn1:"explicit,tag:1"`
	APOptions              asn1.BitString `asn1:"explicit,tag:2"`
	Ticket                 asn1.RawValue  `asn1:"explicit,tag:3"`
	EncryptedAuthenticator EncryptedData  `asn1:"explicit,tag:4"`
}

type APReq struct {
	PVNO                   int            `asn1:"explicit,tag:0"`
	MsgType                int            `asn1:"explicit,tag:1"`
	APOptions              asn1.BitString `asn1:"explicit,tag:2"`
	Ticket                 Ticket         `asn1:"explicit,tag:3"`
	EncryptedAuthenticator EncryptedData  `asn1:"explicit,tag:4"`
	Authenticator          Authenticator  `asn1:"optional"`
}

type Authenticator struct {
	AVNO              int               `asn1:"explicit,tag:0"`
	CRealm            string            `asn1:"generalstring,explicit,tag:1"`
	CName             PrincipalName     `asn1:"explicit,tag:2"`
	Cksum             Checksum          `asn1:"explicit,optional,tag:3"`
	Cusec             int               `asn1:"explicit,tag:4"`
	CTime             time.Time         `asn1:"generalized,explicit,tag:5"`
	SubKey            EncryptionKey     `asn1:"explicit,optional,tag:6"`
	SeqNumber         int64             `asn1:"explicit,optional,tag:7"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:8"`
}

func NewAPReq(apOptions asn1.BitString, ticket Ticket, encryptedAuthenticator EncryptedData) (*APReq, error) {
	req := &APReq{
		PVNO:                   PVNO,
		MsgType:                KRB_AP_REQ,
		APOptions:              apOptions,
		Ticket:                 ticket,
		EncryptedAuthenticator: encryptedAuthenticator,
	}

	return req, nil
}

func (a *APReq) Marshal() ([]byte, error) {
	rawticket, err := a.Ticket.RawValue()
	if err != nil {
		return nil, err
	}

	ticketBytes, err := asn1.Marshal(*rawticket)
	if err != nil {
		return nil, err
	}

	ticket := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        3,
		Bytes:      ticketBytes,
	}

	m := marshalAPReq{
		PVNO:                   a.PVNO,
		MsgType:                a.MsgType,
		APOptions:              a.APOptions,
		Ticket:                 ticket,
		EncryptedAuthenticator: a.EncryptedAuthenticator,
	}

	return asn1.MarshalWithParams(m, fmt.Sprintf("application,explicit,tag:%d", TagAPREQ))
}

func NewAuthenticator(realm string, cname PrincipalName) (*Authenticator, error) {
	now := time.Now().UTC()
	auth := &Authenticator{
		AVNO:   PVNO,
		CRealm: realm,
		CName:  cname,
		Cksum:  Checksum{},
		Cusec:  microseconds(now),
		CTime:  now,
	}

	return auth, nil
}

func (auth *Authenticator) Marshal() ([]byte, error) {
	return asn1.MarshalWithParams(*auth, fmt.Sprintf("application,explicit,tag:%d", TagAuthenticator))
}

func (auth *Authenticator) Encrypt(key EncryptionKey, usage uint32) (*EncryptedData, error) {
	b, err := auth.Marshal()
	if err != nil {
		return nil, err
	}

	encryptedAuthenticator := &EncryptedData{}
	if err := encryptedAuthenticator.Encrypt(key.KeyType, key.KeyValue, b, usage); err != nil {
		return nil, err
	}

	return encryptedAuthenticator, nil
}
