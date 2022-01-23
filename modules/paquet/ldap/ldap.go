package ldap

import (
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

func (l *LDAPClient) Connect(host string, port int) error {
	con, err := ldapv3.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}

	l.l = con

	return nil
}

func (l *LDAPClient) Close() {
	l.l.Close()
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

func (l *LDAPClient) Search(searchFilter string, attributes []string, sizeLimit int) ([]map[string]string, error) {
	searchRequest := ldapv3.NewSearchRequest(
		l.Base,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, sizeLimit, 0, false,
		searchFilter,
		attributes,
		nil,
	)

	sr, err := l.l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	results := make([]map[string]string, 0)
	for _, entry := range sr.Entries {
		result := make(map[string]string)
		result["dn"] = entry.DN
		for _, attr := range attributes {
			result[attr] = entry.GetAttributeValue(attr)
		}

		results = append(results, result)
	}

	return results, nil
}
