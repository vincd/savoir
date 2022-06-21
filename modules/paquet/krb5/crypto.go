package krb5

import (
	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.1
const (
	KeyUsageAsReqPaEncTimestamp   uint32 = 1
	KeyUsageAsRepTgsRepTicket     uint32 = 2
	KeyUsageAsRepEncryptedPart    uint32 = 3
	KeyUsageTgsReqPaAuthenticator uint32 = 7
	KeyUsageApReqAuthenticator    uint32 = 11
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.9
type EncryptedData struct {
	EType int32 `asn1:"explicit,tag:0"`
	// TODO: this is `kvno    [1] UInt32 OPTIONAL,` in the rfc not int
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.9
type EncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.9
type Checksum struct {
	CksumType int32  `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}

func (k *EncryptedData) Encrypt(eType int32, key []byte, b []byte, usage uint32) error {
	if eType == 0 {
		k.EType = 0
		// TODO: uncomment this line when exporting kirbi tickets to Rubeus
		// k.KVNO = PVNO
		k.Cipher = b

		return nil
	}

	et, err := crypto.NewEType(eType)
	if err != nil {
		return err
	}

	encData, err := et.EncryptMessage(key, b, usage)
	if err != nil {
		return err
	}

	k.EType = et.GetEtype()
	k.KVNO = PVNO
	k.Cipher = encData

	return nil
}

func (k *EncryptedData) Decrypt(key []byte, usage uint32) ([]byte, error) {
	if k.EType == 0 {
		return k.Cipher, nil
	}

	et, err := crypto.NewEType(k.EType)
	if err != nil {
		return nil, err
	}

	return et.DecryptMessage(key, k.Cipher, usage)
}
