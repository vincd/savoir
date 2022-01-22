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
	var request string
	var enctype string
	var dcIp string

	var askTgtCmd = &cobra.Command{
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

			if len(request) == 0 {
				return fmt.Errorf("Please specify a username to request the TGS.")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cred := &krb5.KRBCred{}

			if len(ticket) > 0 {
				kirbi, err := krb5.NewKrbCredFromFile(ticket)
				if err != nil {
					return fmt.Errorf("Cannot load kirbi: %s", err)
				}

				cred = kirbi
			} else {
				tgt, err := krb5.AskTGT(domain, username, password, keyBytes, paramStringToEType(strings.ToLower(enctype)), dcIp, false)
				if err != nil {
					return fmt.Errorf("Cannot ask TGT: %s", err)
				}

				cred = tgt.Credentials()
			}

			principalName := krb5.PrincipalName{
				NameType:   krb5.KRB_NT_MS_PRINCIPAL,
				NameString: []string{fmt.Sprintf("%s\\%s", domain, "karen")},
			}

			tgs, err := krb5.AskTGSWithKirbi(domain, principalName, cred, dcIp)
			if err != nil {
				return fmt.Errorf("Cannot ask TGS: %s", err)
			}

			fmt.Printf("%s\n", tgs.HashString("karen", "ubh.lab/karen"))

			return nil
		},
	}
	askTgtCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to target")
	askTgtCmd.Flags().StringVarP(&username, "username", "u", "", "Username of the targeted user")
	askTgtCmd.Flags().StringVarP(&password, "password", "p", "", "Password of the targeted user")
	askTgtCmd.Flags().StringVarP(&ticket, "ticket", "t", "", "Kirbi file containing a TGT")
	askTgtCmd.Flags().StringVarP(&key, "key", "k", "", "Secret key of the targeted user (derivated from password)")
	askTgtCmd.Flags().StringVarP(&request, "request", "r", "", "Ask a TGS for this user")
	askTgtCmd.Flags().StringVarP(&enctype, "enctype", "e", "aes256", "Encryption type: rc4, aes128 or aes256")
	askTgtCmd.Flags().StringVarP(&dcIp, "dc-ip", "", "", "IP of the KDC (Domain controler)")

	Command.AddCommand(askTgtCmd)
}
