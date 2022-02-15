package krb5

import (
	"strings"
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-5.2.2
type PrincipalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

// Returns a ServiceName (sname) foe the servicename string (seprated by `/`)
// The NameType depends on the service name structure: `service-class/hostname-FQDN(:port)(/arbitrary-name)`
func NewServiceName(serviceName string) PrincipalName {
	serviceNameSplited := strings.Split(serviceName, "/")

	if len(serviceNameSplited) == 1 {
		return PrincipalName{
			NameType:   KRB_NT_PRINCIPAL,
			NameString: serviceNameSplited,
		}
	} else {
		return PrincipalName{
			NameType:   KRB_NT_SRV_INST,
			NameString: serviceNameSplited,
		}
	}
}

func NewKrbtgtName(domain string) PrincipalName {
	return PrincipalName{
		NameType:   KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", domain},
	}
}
