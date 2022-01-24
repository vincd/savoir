package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
)

func init() {
	var domain string
	var username string
	var password string
	var ticket string
	var key string
	var keyBytes []byte
	var service string
	var enctype string
	var dcIp string
	var outputFile string

	var askTgsCmd = &cobra.Command{
		Use:   "asktgs",
		Short: "Ask a TGS to the KDC",
		Long:  `Ask a TGS to the KDC`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(password) > 0 && len(key) > 0 {
				return fmt.Errorf("Please specify the user password OR a derivated key.")
			}

			if len(key) > 0 {
				b, err := hex.DecodeString(key)
				if err != nil {
					return fmt.Errorf("Cannot unhexlify key value.")
				}

				keyBytes = b
			}

			if _, ok := encTypeMapping[strings.ToLower(enctype)]; !ok {
				return fmt.Errorf("enctype value is not valid.")
			}

			if len(service) == 0 {
				return fmt.Errorf("Please specify a SPN.")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			tgtCred := &krb5.KRBCred{}

			if len(ticket) > 0 {
				kirbi, err := krb5.NewKrbCredFromFile(ticket)
				if err != nil {
					return fmt.Errorf("Cannot load kirbi: %s", err)
				}

				tgtCred = kirbi
			} else {
				tgt, err := krb5.AskTGT(domain, username, password, keyBytes, paramStringToEType(strings.ToLower(enctype)), dcIp, false, false)
				if err != nil {
					return fmt.Errorf("Cannot ask TGT: %s", err)
				}

				tgtCred = tgt.Credentials()
			}

			principalName := krb5.PrincipalName{
				NameType:   krb5.KRB_NT_SRV_INST,
				NameString: []string{service},
			}

			tgs, err := krb5.AskTGSWithKirbi(domain, principalName, tgtCred, dcIp)
			if err != nil {
				return fmt.Errorf("Cannot ask TGS for SPN %s: %s", service, err)
			}

			tgsCred := tgs.Credentials()
			if len(outputFile) > 0 {
				if err := tgsCred.SaveToFile(outputFile); err != nil {
					return err
				}
				fmt.Printf("TGS saved to %s.\n", outputFile)
			} else {
				b64, err := tgsCred.Base64()
				if err != nil {
					return fmt.Errorf("Cannot encode TGS to base64: %s", err)
				}

				fmt.Printf("%s\n", b64)
			}

			return nil
		},
	}

	askTgsCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to target")
	askTgsCmd.Flags().StringVarP(&username, "username", "u", "", "Username of the targeted user")
	askTgsCmd.Flags().StringVarP(&password, "password", "p", "", "Password of the targeted user")
	askTgsCmd.Flags().StringVarP(&ticket, "ticket", "t", "", "Kirbi file containing a TGT")
	askTgsCmd.Flags().StringVarP(&key, "key", "k", "", "Secret key of the targeted user (derivated from password)")
	askTgsCmd.Flags().StringVarP(&service, "service", "s", "", "Ask a TGS for this SPN")
	askTgsCmd.Flags().StringVarP(&enctype, "enctype", "e", "aes256", "Encryption type: rc4, aes128 or aes256")
	askTgsCmd.Flags().StringVarP(&dcIp, "dc-ip", "", "", "IP of the KDC (Domain controler)")
	askTgsCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the TGS to a kirbi file")

	Command.AddCommand(askTgsCmd)
}
