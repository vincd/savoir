package spnego

import (
	"fmt"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/utils/asn1"
)

type ContextFlags asn1.BitString

// https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.1
type NegTokenInit struct {
	MechTypes      []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags       ContextFlags            `asn1:"explicit,optional,tag:1"`
	MechTokenBytes []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC    []byte                  `asn1:"explicit,optional,omitempty,tag:3"`
}

// The SPNEGO pseudo mechanism is identified by the Object Identifier
// iso.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2).
var OidSpnegoUUID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

var OidcMskrb5Microsoftkerberos5 = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}

func NewNegTokenInit(apReq *krb5.APReq) (*NegTokenInit, error) {
	mechTypes := []asn1.ObjectIdentifier{
		OidcMskrb5Microsoftkerberos5,
	}

	mechTokenBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("could not marshall APReq on NegTokenInit: %s", err)
	}

	negTokenInit := &NegTokenInit{
		MechTypes:      mechTypes,
		MechTokenBytes: mechTokenBytes,
	}

	return negTokenInit, nil
}

// https://datatracker.ietf.org/doc/html/rfc4178#section-4.2
func GSSAPI(negTokenInit *NegTokenInit) ([]byte, error) {
	oid, err := asn1.Marshal(OidSpnegoUUID)
	if err != nil {
		return nil, fmt.Errorf("could not marshall GSSAPI spnego OID: %s", err)
	}

	// SPNEGO_NEG_TOKEN_INIT = 0xa0
	// asn1.ClassContextSpecific and isCompound = true (0xa0 = 2 << 6 | 0x20)
	m, err := asn1.MarshalWithRawValue(*negTokenInit, asn1.ClassContextSpecific, 0, true)
	if err != nil {
		return nil, fmt.Errorf("could not marshall GSSAPI NegTokenInit: %s", err)
	}

	// ASN1_AID = 0x60
	// asn1.ClassApplication and isCompound = true (0x60 = 1 << 6 | 0x20)
	return asn1.MarshalWithRawValueBytes(append(oid, m...), asn1.ClassApplication, 0, true)
}
