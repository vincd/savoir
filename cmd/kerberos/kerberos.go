package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
	"github.com/vincd/savoir/utils"
)

var Command = &cobra.Command{
	Use:   "kerberos",
	Short: "Do some Kerberos stuff",
	Long:  `Kerberos stuff`,
}

// Add Domain name and Domain Controler IP as required flags
func commandAddKerberosDomainFlags(cmd *cobra.Command, dcIp *string, socksAddress *string) {
	cmd.Flags().StringVarP(dcIp, "dc-ip", "", "", "IP of the KDC (Domain controler)")
	cobra.MarkFlagRequired(cmd.Flags(), "dc-ip")
	cmd.Flags().StringVarP(socksAddress, "socks", "", "", "Socks proxy server (host:port)")
}

// Add flags to authenticate the domain user (the requester): domain, ticket or username, password or key
// When we use a ticket then the username is not required
func commandAddDomainUserCredentialsFlags(cmd *cobra.Command, domain *string, username *string, password *string, key *string, ticket *string) {
	cmd.Flags().StringVarP(domain, "domain", "d", "", "Domain to target")
	cmd.Flags().StringVarP(username, "username", "u", "", "Username of the targeted user")
	cmd.Flags().StringVarP(password, "password", "p", "", "Password of the targeted user")
	cmd.Flags().StringVarP(key, "key", "k", "", "Secret key of the targeted user (derivated from password)")

	if ticket != nil {
		cmd.Flags().StringVarP(ticket, "ticket", "", "", "Kirbi file containing a TGT")
	} else {
		cobra.MarkFlagRequired(cmd.Flags(), "domain")
		cobra.MarkFlagRequired(cmd.Flags(), "username")
	}
}

// Add flags to authenticate the domain user (the requester): domain, username, password or key
func commandAddDomainUserFlags(cmd *cobra.Command, domain *string, username *string, password *string, key *string) {
	commandAddDomainUserCredentialsFlags(cmd, domain, username, password, key, nil)
}

// Add flags to authenticate the domain user (the requester): domain, ticket or username, password or key
func commandAddDomainUserFlagsWithTicket(cmd *cobra.Command, domain *string, username *string, password *string, key *string, ticket *string) {
	commandAddDomainUserCredentialsFlags(cmd, domain, username, password, key, ticket)
}

// Add flags to connect to a LDAP endpoint
func commandAddLDAPFlags(cmd *cobra.Command, username *string, password *string, sizeLimit *int) {
	cmd.Flags().StringVarP(username, "ldap-user", "", "", "Username to connect to LDAP")
	cmd.Flags().StringVarP(password, "ldap-password", "", "", "Password to connect to LDAP")
	cmd.Flags().IntVarP(sizeLimit, "ldap-size-limit", "", 1000, "LDAP size limit: if there is more results, there will be discarded")
	// TODO: add LDAPS & PORT
}

// Add flag to choose the Encryption Type (EType)
func commandAddKerberosETypeFlag(cmd *cobra.Command, enctype *string) {
	commandAddKerberosETypeFlagWithDefaultValue(cmd, enctype, "aes256")
}

// Add flag to choose the Encryption Type (EType)
func commandAddKerberosETypeFlagWithDefaultValue(cmd *cobra.Command, enctype *string, defaultEType string) {
	cmd.Flags().StringVarP(enctype, "enctype", "e", defaultEType, "Encryption type: rc4, aes128 or aes256")
}

// Add flag to choose a hash format on the output (Hashcat or JonTheRipper)
func commandAddFormatFlag(cmd *cobra.Command, format *string) {
	cmd.Flags().StringVarP(format, "format", "f", "", "Output hash as John the Ripper or Hashcat format")
}

// Default supported EType. It includes the EType name (rc4, aes128, ...) and
// also the number (23, 18, ...)
var supportedETypeMapping = map[string]int32{
	// "3":      crypto.DES_CBC_MD5,
	// "des":    crypto.DES_CBC_MD5,
	"17":     crypto.AES128_CTS_HMAC_SHA1_96,
	"aes128": crypto.AES128_CTS_HMAC_SHA1_96,
	"18":     crypto.AES256_CTS_HMAC_SHA1_96,
	"aes256": crypto.AES256_CTS_HMAC_SHA1_96,
	"23":     crypto.RC4_HMAC,
	"rc4":    crypto.RC4_HMAC,
	"ntlm":   crypto.RC4_HMAC,
}

// Returns the EType from the flag and returns aes256 as a default value
func getETypeFromFlagValue(enctype string) int32 {
	if val, ok := supportedETypeMapping[strings.ToLower(enctype)]; ok {
		return val
	}

	return supportedETypeMapping["aes256"]
}

// Parse the key string to a byte slice
func getKeyFlagValue(key string) ([]byte, error) {
	b, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("flag --key value cannot be unhexlify")
	}

	return b, nil
}

// Validate a domain user credentials
func validateDomainUserFlags(username string, password string, key string) error {
	// Even if username is required, check if the username is not empty
	if len(username) == 0 {
		return fmt.Errorf("flag --username cannot be empty")
	}

	if len(password) > 0 && len(key) > 0 {
		return fmt.Errorf("flags --password and --key cannot be set on the same command")
	}

	if len(key) > 0 {
		if _, err := hex.DecodeString(key); err != nil {
			return fmt.Errorf("flag --key is not a valid hex string")
		}
	}

	return nil
}

// Validate a domain user credentials and a ticket
func validateDomainUserFlagsWithTicket(username string, password string, key string, ticket string) error {
	if err := validateDomainUserFlags(username, password, key); err != nil {
		return err
	}

	if len(ticket) > 0 && (len(password) > 0 || len(key) > 0) {
		return fmt.Errorf("flags --ticket and --password or --key cannot be set on the same command")
	}
	return nil
}

// Validate the flag has the EType values from the supported ones. Call this function in `Args`.
func validateETypeFlag(enctype string) error {
	if _, ok := supportedETypeMapping[strings.ToLower(enctype)]; !ok {
		return fmt.Errorf("flag --enctype value is not valid")
	}

	return nil
}

// Validate the hash format is correct. Call this function in `Args`.
func validateFormatFlag(format string) error {
	if format != "" && format != "john" && format != "hashcat" {
		return fmt.Errorf("flag --format value should be `john` or `hashcat`")
	}

	return nil
}

// Print information about the domain
func printDomainInformation(domain string, dcIp string) {
	fmt.Printf("[*] Target domain: %s (%s)\n", domain, dcIp)
}

// Get dialer to KDC (using socks and timeout)
func getKdcDialer(socksAddress string) (proxy.Dialer, error) {
	return utils.GetDialerWithSocks(socksAddress)
}
