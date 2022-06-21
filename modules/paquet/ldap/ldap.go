package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

type LDAPClient struct {
	Host string
	Port int
	Base string
	l    *ldapv3.Conn
}

func NewLDAPClient() (*LDAPClient, error) {
	l := &LDAPClient{}

	return l, nil
}

func (l *LDAPClient) Connect(host string, port int, secure bool) error {
	if secure {
		tls := &tls.Config{InsecureSkipVerify: true}
		con, err := ldapv3.DialTLS("tcp", fmt.Sprintf("%s:%d", host, port), tls)
		if err != nil {
			return err
		}
		l.l = con
	} else {
		con, err := ldapv3.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
		if err != nil {
			return err
		}
		l.l = con
	}

	return nil
}

func (l *LDAPClient) Close() {
	l.l.Close()
}

// Authenticate to the ldap server using an account and the password
func (l *LDAPClient) AuthenticateWithAccount(username string, password string) error {
	if err := l.l.Bind(username, password); err != nil {
		return err
	}

	sr := ldapv3.NewSearchRequest(
		"",
		ldapv3.ScopeBaseObject,
		ldapv3.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil,
	)

	res, err := l.l.Search(sr)
	if err != nil {
		return fmt.Errorf("cannot search default naming context: %s", err)
	}

	if len(res.Entries) == 0 {
		return fmt.Errorf("ldap naming request search returns no result")
	}

	defaultNamingContext := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if defaultNamingContext == "" {
		return fmt.Errorf("ldap naming request search returns an empty defaultNamingContext")
	}

	l.Base = defaultNamingContext

	return nil
}

// Authenticate to the ldap server using a domain account and the password
func (l *LDAPClient) AuthenticateWithDomainAccount(domain string, username string, password string) error {
	if err := l.l.NTLMBind(domain, username, password); err != nil {
		return err
	}

	l.Base = "dc=" + strings.Join(strings.Split(domain, "."), ",dc=")

	return nil
}

// Authenticate to the ldap server using a domain account and the hash password
func (l *LDAPClient) AuthenticateWithDomainAccountAndHash(domain string, username string, hash string) error {
	if err := l.l.NTLMBindWithHash(domain, username, hash); err != nil {
		return err
	}

	l.Base = "dc=" + strings.Join(strings.Split(domain, "."), ",dc=")

	return nil
}

// Query the LDAP server and returns entries with attributes. Returns sizeLimit results even
// if there is more results. Returns a slice of map for each attribute pointing to a list of values
// [
//     {
//         "cn": [
//             "test"
//         ],
//         "dn": [
//             "CN=test,CN=Users,DN=UBH,DN=lab"
//         ],
//         "sAMAccountType": [
//             "805306368"
//         ],
//         "samAccountName": [
//             "test"
//         ],
//         "servicePrincipalName": [
//             "MSSQLSvc/server01.UBH.LAB:1433",
//             "MSSQLSvc/server02.UBH.LAB:1433",
//         ]
//     }
// ]
func (l *LDAPClient) SearchWithSizeLimit(searchFilter string, attributes []string, sizeLimit int) ([]map[string][]string, error) {
	searchRequest := ldapv3.NewSearchRequest(
		l.Base,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, sizeLimit, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := l.l.Search(searchRequest)
	if err != nil {
		if ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultReferral) {
			// We parse the Base from the domain name, then we may have a wrong result here
			return nil, fmt.Errorf("base DN is not correct (%s), please check the domain provided", l.Base)
		} else if ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultSizeLimitExceeded) {
			// We've more results, then ignore this error and parse the entries
		} else {
			return nil, fmt.Errorf("cannot search: %s", err)
		}
	}

	results := make([]map[string][]string, 0)
	for _, entry := range sr.Entries {
		result := make(map[string][]string)
		result["dn"] = []string{entry.DN}
		for _, attr := range attributes {
			// Use FoldAttribute because the attributes are case sensitive
			// Returns a string slice because some attributs may contains multiple values (servicePrincipalName)
			result[attr] = entry.GetEqualFoldAttributeValues(attr)
		}

		results = append(results, result)
	}

	return results, nil
}
