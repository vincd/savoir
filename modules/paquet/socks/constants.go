package socks

const (
	Version5 = 0x05

	AddrTypeIPv4 = 0x01
	AddrTypeFQDN = 0x03
	AddrTypeIPv6 = 0x04

	CmdConnect = 0x01 // establishes an active-open forward proxy connection
	cmdBind    = 0x02 // establishes a passive-open forward proxy connection

	AuthMethodNotRequired = 0x00 // no authentication required
	UsernamePassword      = 0x02 // use username/password
	NoAcceptableMethods   = 0xff // no acceptable authentication methods

	AuthUsernamePasswordVersion = 0x01
	AuthStatusSucceeded         = 0x00
	AuthStatusFailure           = 0x01

	StatusSucceeded                          = 0x00
	StatusGeneralFailure                     = 0x01
	StatusConnectionNotAllewedByRuleset      = 0x02
	StatusNetworkUnreachable                 = 0x03
	StatusHostUnreachable                    = 0x04
	StatusConnectionTefusedByDestinationHost = 0x05
	StatusTTLExpired                         = 0x06
	StatusCommandNotSupportedProtocolError   = 0x07
	StatusAddressTypeNotSupported            = 0x08
)
