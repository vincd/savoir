package krb5

import (
	"time"

	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7
type PAData struct {
	PADataType  int32  `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.2
type PAEncTsEnc struct {
	PATimestamp time.Time `asn1:"generalized,explicit,tag:0"`
	PAUsec      int       `asn1:"optional,explicit,tag:1"`
}

type KerbPaPacRequest struct {
	IncludePac bool `asn1:"explicit,tag:0"`
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.4
type EtypeInfoEntry struct {
	EType int32  `asn1:"explicit,tag:0"`
	Salt  string `asn1:"optional,explicit,generalstring,tag:1"`
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.7.5
type EtypeInfo2Entry struct {
	EType     int32  `asn1:"explicit,tag:0"`
	Salt      string `asn1:"optional,explicit,generalstring,tag:1"`
	S2KParams []byte `asn1:"optional,explicit,tag:2"`
}

func NewPAData(dataType int32, val interface{}) (*PAData, error) {
	dataValue, err := asn1.Marshal(val)
	if err != nil {
		return nil, err
	}

	paData := &PAData{
		PADataType:  dataType,
		PADataValue: dataValue,
	}

	return paData, nil
}

func NewPADataEncrypted(dataType int32, val interface{}, eType int32, key []byte) (*PAData, error) {
	encodedValue, err := asn1.Marshal(val)
	if err != nil {
		return nil, err
	}

	encryptedTsEncData := EncryptedData{}
	if err := encryptedTsEncData.Encrypt(eType, key, encodedValue, KeyUsageAsReqPaEncTimestamp); err != nil {
		return nil, err
	}

	return NewPAData(dataType, encryptedTsEncData)
}

func NewKerbPaPacRequest(includePac bool) (*PAData, error) {
	return NewPAData(PA_PAC_REQUEST, KerbPaPacRequest{IncludePac: includePac})
}

func NewPAEncTsEnc() PAEncTsEnc {
	now := time.Now().UTC()

	pa := PAEncTsEnc{
		PATimestamp: now,
		PAUsec:      microseconds(now),
	}

	return pa
}
