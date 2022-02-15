package krb5

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.5
type HostAddress struct {
	AddrType int32  `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

type HostAddresses []HostAddress

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.10
const (
	TagTicket         = 1
	TagAuthenticator  = 2
	TagEncTicketPart  = 3
	TagASREQ          = 10
	TagTGSREQ         = 12
	TagASREP          = 11
	TagTGSREP         = 13
	TagAPREQ          = 14
	TagAPREP          = 15
	TagKRBSafe        = 20
	TagKRBPriv        = 21
	TagKRBCred        = 22
	TagEncASRepPart   = 25
	TagEncTGSRepPart  = 26
	TagEncAPRepPart   = 27
	TagEncKrbPrivPart = 28
	TagEncKrbCredPart = 29
	TagKRBError       = 30
)
