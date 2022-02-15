package kerberos

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
)

func init() {
	var domain string
	var username string
	var password string
	var ticket string
	var key string
	var service string
	var enctype string
	var dcIp string
	var outputFile string
	var serviceKey string
	var serviceKeyBytes []byte

	var askTgsCmd = &cobra.Command{
		Use:   "asktgs",
		Short: "Ask a TGS to the KDC",
		Long:  `Ask a TGS to the KDC`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := validateDomainUserFlagsWithTicket(username, password, key, ticket); err != nil {
				return err
			}

			if err := validateETypeFlag(enctype); err != nil {
				return err
			}

			if len(service) == 0 {
				return fmt.Errorf("flag --service cannot be empty")
			}

			b, err := hex.DecodeString(serviceKey)
			if err != nil {
				return fmt.Errorf("flag --service-key is not a valid hex string")
			}
			serviceKeyBytes = b

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var tgtCred *krb5.KRBCred

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

				fmt.Printf("[*] Use username and password/key as credentials\n")
				tgt, err := krb5.AskTGT(domain, username, password, keyBytes, getETypeFromFlagValue(enctype), dcIp, false, false)
				if err != nil {
					return fmt.Errorf("cannot ask TGT: %s", err)
				}

				tgtCred = tgt.Credentials()
			}

			fmt.Printf("[*] Asking TGS for principal: %s\n", service)
			tgs, err := krb5.AskTGSWithKirbi(domain, krb5.NewServiceName(service), tgtCred, dcIp)
			if err != nil {
				return fmt.Errorf("cannot ask TGS for principal %s: %s", service, err)
			}

			cred := tgs.Credentials()
			fmt.Printf("%s\n", cred.DisplayTicket(true, false, serviceKeyBytes))

			if len(outputFile) > 0 {
				if err := cred.SaveToFile(outputFile); err != nil {
					return err
				}

				fmt.Printf("[*] TGS saved to %s.\n", outputFile)
			}

			return nil
		},
	}

	commandAddKerberosDomainFlags(askTgsCmd, &domain, &dcIp)
	commandAddDomainUserFlagsWithTicket(askTgsCmd, &username, &password, &key, &ticket)
	commandAddKerberosETypeFlag(askTgsCmd, &enctype)
	askTgsCmd.Flags().StringVarP(&service, "service", "s", "", "Ask a TGS for this SPN")
	cobra.MarkFlagRequired(askTgsCmd.Flags(), "service")
	askTgsCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the TGS to a kirbi file")
	askTgsCmd.Flags().StringVarP(&serviceKey, "service-key", "", "", "Service Key to decrypt PAC informations")

	Command.AddCommand(askTgsCmd)
}
