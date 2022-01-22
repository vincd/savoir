package krb5

import (
	"fmt"
	"time"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.9
// https://datatracker.ietf.org/doc/html/rfc4120#section-5.9.1
type KRBError struct {
	PVNO      int           `asn1:"explicit,tag:0"`
	MsgType   int           `asn1:"explicit,tag:1"`
	CTime     time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	Cusec     int           `asn1:"optional,explicit,tag:3"`
	STime     time.Time     `asn1:"generalized,explicit,tag:4"`
	Susec     int           `asn1:"explicit,tag:5"`
	ErrorCode int32         `asn1:"explicit,tag:6"`
	CRealm    string        `asn1:"generalstring,optional,explicit,tag:7"`
	CName     PrincipalName `asn1:"optional,explicit,tag:8"`
	Realm     string        `asn1:"generalstring,explicit,tag:9"`
	SName     PrincipalName `asn1:"explicit,tag:10"`
	EText     string        `asn1:"generalstring,optional,explicit,tag:11"`
	EData     []byte        `asn1:"optional,explicit,tag:12"`
}

func (k *KRBError) Unmarshal(b []byte) error {
	return unmarshalMessage(b, k, KRB_ERROR)
}

func (k *KRBError) String() string {
	if val, ok := errorcodeById[k.ErrorCode]; ok {
		return fmt.Sprintf("[KRBError] %s", val)
	}

	return fmt.Sprintf("[KRBError] Unknow error with id %d", k.ErrorCode)
}

func (k *KRBError) Error() error {
	return fmt.Errorf(k.String())
}
