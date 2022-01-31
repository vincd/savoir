package kerberos

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
)

func init() {
	var domain string
	var username string
	var password string
	var key string
	var enctype string
	var dcIp string
	var noPac bool
	var format string
	var outputFile string

	var askTgtCmd = &cobra.Command{
		Use:   "asktgt",
		Short: "Ask a TGT to the KDC",
		Long:  `Ask a TGT to the KDC`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateDomainUserFlags(username, password, key); err != nil {
				return err
			}

			if err := validateFormatFlag(format); err != nil {
				return err
			}

			if err := validateETypeFlag(enctype); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			keyBytes, err := getKeyFlagValue(key)
			if err != nil {
				return err
			}

			fmt.Printf("[*] Ask AS-Rep for user %s\n", username)
			tgt, err := krb5.AskTGT(domain, username, password, keyBytes, getETypeFromFlagValue(enctype), dcIp, false, noPac)
			if err != nil {
				return err
			}

			// Concert to a KRBCred
			cred := tgt.Credentials()
			fmt.Printf("%s\n", cred.DisplayTicket(true, false))

			// We don't print the hashes in `DisplayTicket`
			if format == "john" {
				fmt.Printf("%s\n", tgt.JohnString())
			} else if format == "hashcat" {
				fmt.Printf("%s\n", tgt.HashcatString())
			}

			if len(outputFile) > 0 {
				if err := cred.SaveToFile(outputFile); err != nil {
					return err
				}

				fmt.Printf("[*] TGT saved to %s.\n", outputFile)
			}

			return nil
		},
	}

	commandAddKerberosDomainFlags(askTgtCmd, &domain, &dcIp)
	commandAddKerberosETypeFlag(askTgtCmd, &enctype)
	commandAddFormatFlag(askTgtCmd, &format)
	commandAddDomainUserFlags(askTgtCmd, &username, &password, &key)
	askTgtCmd.Flags().BoolVarP(&noPac, "no-pac", "", false, "Request a TGT without PAC")
	askTgtCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Save the TGT to a kirbi file")

	Command.AddCommand(askTgtCmd)
}
