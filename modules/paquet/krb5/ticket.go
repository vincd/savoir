package krb5

import (
	"fmt"
	"time"

	"github.com/vincd/savoir/utils/asn1"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.3
type Ticket struct {
	TktVNO           int           `asn1:"explicit,tag:0"`
	Realm            string        `asn1:"generalstring,explicit,tag:1"`
	SName            PrincipalName `asn1:"explicit,tag:2"`
	EncPart          EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart `asn1:"optional"`
}

type EncTicketPart struct {
	Flags             asn1.BitString    `asn1:"explicit,tag:0"`
	Key               EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string            `asn1:"generalstring,explicit,tag:2"`
	CName             PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding `asn1:"explicit,tag:4"`
	AuthTime          time.Time         `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time         `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time         `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time         `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

type SequenceOfRawTickets []asn1.RawValue

func (t *Ticket) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, t, fmt.Sprintf("application,explicit,tag:%d", TagTicket))
	return err
}

func (t *Ticket) Marshal() ([]byte, error) {
	return asn1.Marshal(*t)
}

func (t *Ticket) RawValue() (*asn1.RawValue, error) {
	buffer, err := t.Marshal()
	if err != nil {
		return nil, err
	}

	r := &asn1.RawValue{
		Class:      asn1.ClassApplication,
		IsCompound: true,
		Tag:        TagTicket,
		Bytes:      buffer,
	}

	return r, nil
}

func (s SequenceOfRawTickets) Tickets() ([]Ticket, error) {
	tickets := make([]Ticket, 0)

	for _, rawTicket := range s {
		ticket := Ticket{}
		// TODO: FullBytes or Bytes ?
		if err := ticket.Unmarshal(rawTicket.FullBytes); err != nil {
			return nil, err
		}

		tickets = append(tickets, ticket)
	}

	return tickets, nil
}

func (s *SequenceOfRawTickets) AddTickets(tickets []Ticket) error {
	for _, ticket := range tickets {
		r, err := ticket.RawValue()
		if err != nil {
			return err
		}

		(*s) = append(*s, *r)
	}

	return nil
}

const (
	TicketFlagsReserved               = 0
	TicketFlagsForwardable            = 1
	TicketFlagsForwarded              = 2
	TicketFlagsProxiable              = 3
	TicketFlagsProxy                  = 4
	TicketFlagsMayPostdate            = 5
	TicketFlagsPostdated              = 6
	TicketFlagsInvalid                = 7
	TicketFlagsRenewable              = 8
	TicketFlagsInitial                = 9
	TicketFlagPreAuthent              = 10
	TicketFlagHwAuthent               = 11
	TicketFlagsTransitedPolicyChecked = 12
	TicketFlagsOkAsDelegate           = 13
)

var ticketFlagsMap = map[int]string{
	TicketFlagsReserved:               "reserved",
	TicketFlagsForwardable:            "forwardable",
	TicketFlagsForwarded:              "forwarded",
	TicketFlagsProxiable:              "proxiable",
	TicketFlagsProxy:                  "proxy",
	TicketFlagsMayPostdate:            "may-postdate",
	TicketFlagsPostdated:              "postdated",
	TicketFlagsInvalid:                "invalid",
	TicketFlagsRenewable:              "renewable",
	TicketFlagsInitial:                "initial",
	TicketFlagPreAuthent:              "pre-authent",
	TicketFlagHwAuthent:               "hw-authent",
	TicketFlagsTransitedPolicyChecked: "transited-policy-checked",
	TicketFlagsOkAsDelegate:           "ok-as-delegate",
}

func ParseTicketFlags(ticketFlags asn1.BitString) []string {
	flags := make([]string, 0)

	// Don't loop over the ticketFlagMap to keep the flags order
	for i := TicketFlagsReserved; i <= TicketFlagsOkAsDelegate; i++ {
		if ticketFlags.At(i) == 1 {
			flags = append(flags, ticketFlagsMap[i])
		}
	}

	return flags
}
