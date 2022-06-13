package ldap

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vincd/savoir/modules/paquet/ldap"
	"github.com/vincd/savoir/utils"
)

var Command = &cobra.Command{
	Use:   "ldap",
	Short: "Interact with LDAP server",
	Long:  `Interact with LDAP server`,
}

func init() {
	var domain string
	var username string
	var password string
	var ntlm string
	var host string
	var port int
	var sizeLimit int
	var query string
	var attributes string
	var isJson bool
	var isSecure bool

	var ldapCmd = &cobra.Command{
		Use:   "query",
		Short: "Query LDAP server",
		Long:  `Query LDAP server`,
		Args: func(cmd *cobra.Command, args []string) error {
			if isSecure && port == 389 {
				port = 636
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ldapClient, err := ldap.NewLDAPClient()
			if err != nil {
				return err
			}

			if err := ldapClient.Connect(host, port, isSecure); err != nil {
				return err
			}
			defer ldapClient.Close()

			if len(password) > 0 {
				if err := ldapClient.AuthenticateWithDomainAccount(domain, username, password); err != nil {
					return err
				}
			} else if len(ntlm) == 32 {
				if err := ldapClient.AuthenticateWithDomainAccountAndHash(domain, username, ntlm); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("please specifiy a password or a hash to authenticate to the LDAP server")
			}

			entries, err := ldapClient.SearchWithSizeLimit(query, strings.Split(attributes, ","), sizeLimit)
			if err != nil {
				return err
			}

			if isJson {
				outputJson, err := utils.PrettyfyJSON(entries)
				if err != nil {
					return err
				}
				fmt.Printf("%s\n", outputJson)
			} else {
				for _, entry := range entries {
					fmt.Printf("%s\n", entry["dn"][0])
					for k, v := range entry {
						if k != "dn" {
							if len(v) == 1 {
								fmt.Printf("  %s: %s\n", k, v[0])
							} else {
								fmt.Printf("  %s:\n", k)
								for _, vi := range v {
									fmt.Printf("    - %s\n", vi)
								}
							}
						}
					}
					fmt.Printf("\n")
				}
			}

			return nil
		},
	}

	ldapCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain (e.g ubh.lab)")
	ldapCmd.Flags().StringVarP(&username, "username", "u", "", "Username of the domain user")
	ldapCmd.Flags().StringVarP(&password, "password", "p", "", "Password of the domain user")
	ldapCmd.Flags().StringVarP(&ntlm, "ntlm", "n", "", "NTLM password hash of the domain user")
	ldapCmd.Flags().StringVarP(&host, "host", "H", "", "LDAP server hostname")
	ldapCmd.Flags().IntVarP(&port, "port", "", 389, "LDAP server port (636 with secure flag set)")
	ldapCmd.Flags().IntVarP(&sizeLimit, "size-limit", "", 1000, "LDAP size limit")
	ldapCmd.Flags().StringVarP(&query, "query", "q", "(&(objectCategory=User))", "Query")
	ldapCmd.Flags().StringVarP(&attributes, "attributes", "a", "cn,sAMAccountName,userAccountControl", "Attributes seprated by a comma")
	ldapCmd.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")
	ldapCmd.Flags().BoolVarP(&isSecure, "secure", "", false, "Use secure connection (change default port to 636)")

	Command.AddCommand(ldapCmd)
}
