package krb5

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"

	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.1
type ASReq struct {
	KDCReq
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.4.1
type TGSReq struct {
	KDCReq
}

type marshalKDCReq struct {
	PVNO    int           `asn1:"explicit,tag:1"`
	MsgType int           `asn1:"explicit,tag:2"`
	PAData  []PAData      `asn1:"explicit,optional,tag:3"`
	ReqBody asn1.RawValue `asn1:"explicit,tag:4"`
}

type KDCReq struct {
	PVNO    int
	MsgType int
	PAData  []PAData
	ReqBody KDCReqBody
	Renewal bool
}

type marshalKDCReqBody struct {
	KDCOptions        asn1.BitString       `asn1:"explicit,tag:0"`
	CName             PrincipalName        `asn1:"explicit,optional,tag:1"`
	Realm             string               `asn1:"generalstring,explicit,tag:2"`
	SName             PrincipalName        `asn1:"explicit,optional,tag:3"`
	From              time.Time            `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time            `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time            `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int                  `asn1:"explicit,tag:7"`
	EType             []int32              `asn1:"explicit,tag:8"`
	Addresses         []HostAddress        `asn1:"explicit,optional,tag:9"`
	EncAuthData       EncryptedData        `asn1:"explicit,optional,tag:10"`
	AdditionalTickets SequenceOfRawTickets `asn1:"explicit,optional,tag:11"`
}

type KDCReqBody struct {
	KDCOptions        asn1.BitString `asn1:"explicit,tag:0"`
	CName             PrincipalName  `asn1:"explicit,optional,tag:1"`
	Realm             string         `asn1:"generalstring,explicit,tag:2"`
	SName             PrincipalName  `asn1:"explicit,optional,tag:3"`
	From              time.Time      `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time      `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time      `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int            `asn1:"explicit,tag:7"`
	EType             []int32        `asn1:"explicit,tag:8"`
	Addresses         []HostAddress  `asn1:"explicit,optional,tag:9"`
	EncAuthData       EncryptedData  `asn1:"explicit,optional,tag:10"`
	AdditionalTickets []Ticket       `asn1:"explicit,optional,tag:11"`
}

func NewASReq(realm string, cname PrincipalName, sname PrincipalName, kFlags asn1.BitString, encType int32) (*ASReq, error) {
	now := time.Now().UTC()
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, fmt.Errorf("Cannot generate nonce: %s", err)
	}

	req := &ASReq{
		KDCReq{
			PVNO:    PVNO,
			MsgType: KRB_AS_REQ,
			PAData:  []PAData{},
			ReqBody: KDCReqBody{
				KDCOptions: kFlags,
				Realm:      strings.ToUpper(realm),
				CName:      cname,
				SName:      sname,
				Till:       now.Add(time.Hour * 24), // Default 1 day
				Nonce:      int(nonce.Int64()),
				EType:      []int32{encType},
			},
		},
	}

	return req, nil
}

func (k *ASReq) Marshal() ([]byte, error) {
	encodedBody, err := k.ReqBody.Marshal()
	if err != nil {
		return nil, err
	}

	m := marshalKDCReq{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		PAData:  k.PAData,
		ReqBody: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Tag:        4,
			Bytes:      encodedBody,
		},
	}

	b, err := asn1.MarshalWithParams(m, fmt.Sprintf("application,explicit,tag:%d", KRB_AS_REQ))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (k *ASReq) Unmarshal(b []byte) error {
	m := &marshalKDCReq{}
	if err := unmarshalMessage(b, m, KRB_AS_REQ); err != nil {
		return err
	}

	k.MsgType = m.MsgType
	k.PAData = m.PAData
	k.PVNO = m.PVNO

	if err := k.ReqBody.Unmarshal(m.ReqBody.Bytes); err != nil {
		return fmt.Errorf("Cannot unmarshal AS_REQ body: %s", err)
	}

	return nil
}

func NewTGSReq(apReq *APReq, realm string, cname PrincipalName, sname PrincipalName, kFlags asn1.BitString, encTypes []int32) (*TGSReq, error) {
	encodedAPReq, err := apReq.Marshal()
	if err != nil {
		return nil, err
	}
	paAPReq := PAData{
		PADataType:  PA_TGS_REQ,
		PADataValue: encodedAPReq,
	}

	now := time.Now().UTC()
	nonce, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, fmt.Errorf("Cannot generate nonce: %s", err)
	}

	req := &TGSReq{
		KDCReq{
			PVNO:    PVNO,
			MsgType: KRB_TGS_REQ,
			PAData:  []PAData{paAPReq},
			ReqBody: KDCReqBody{
				KDCOptions: kFlags,
				Realm:      strings.ToUpper(realm),
				CName:      cname,
				SName:      sname,
				Till:       now.Add(time.Hour * 24), // Default 1 day
				Nonce:      int(nonce.Int64()),
				EType:      encTypes,
			},
		},
	}

	return req, nil
}

func (k *TGSReq) Marshal() ([]byte, error) {
	encodedBody, err := k.ReqBody.Marshal()
	if err != nil {
		return nil, err
	}

	m := marshalKDCReq{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		PAData:  k.PAData,
		ReqBody: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Tag:        4,
			Bytes:      encodedBody,
		},
	}

	b, err := asn1.MarshalWithParams(m, fmt.Sprintf("application,explicit,tag:%d", TagTGSREQ))
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (k *TGSReq) Unmarshal(b []byte) error {
	return fmt.Errorf("TGSReq::Unmarshall is not implemented")
}

func (k *KDCReqBody) Marshal() ([]byte, error) {
	m := marshalKDCReqBody{
		KDCOptions:  k.KDCOptions,
		CName:       k.CName,
		Realm:       k.Realm,
		SName:       k.SName,
		From:        k.From,
		Till:        k.Till,
		RTime:       k.RTime,
		Nonce:       k.Nonce,
		EType:       k.EType,
		Addresses:   k.Addresses,
		EncAuthData: k.EncAuthData,
	}

	if err := m.AdditionalTickets.AddTickets(k.AdditionalTickets); err != nil {
		return nil, err
	}

	return asn1.Marshal(m)
}

func (k *KDCReqBody) Unmarshal(b []byte) error {
	m := &marshalKDCReqBody{}
	if _, err := asn1.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("Cannot unmarshal KDC_REQ body: %s", err)
	}

	additionalTickets, err := m.AdditionalTickets.Tickets()
	if err != nil {
		return fmt.Errorf("Cannot get AdditionalTickets: %s", err)
	}

	k.KDCOptions = m.KDCOptions
	k.CName = m.CName
	k.Realm = m.Realm
	k.SName = m.SName
	k.From = m.From
	k.Till = m.Till
	k.RTime = m.RTime
	k.Nonce = m.Nonce
	k.EType = m.EType
	k.Addresses = m.Addresses
	k.EncAuthData = m.EncAuthData
	k.AdditionalTickets = additionalTickets

	return nil
}
