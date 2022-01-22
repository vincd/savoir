package kerberos

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
)

var encTypeMapping = map[string]int32{
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

func paramStringToEType(enctype string) int32 {
	if val, ok := encTypeMapping[enctype]; ok {
		return val
	}

	return encTypeMapping["aes256"]
}

func init() {
	var domain string
	var username string
	var password string
	var key string
	var keyBytes []byte
	var enctype string
	var dcIp string
	var noPac bool
	var format string
	var outputFile string

	var askTgtCmd = &cobra.Command{
		Use:   "asktgt",
		Short: "Ask a TGT to the KDC",
		Long:  `Ask a TGT to the KDC`,
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

			if format != "" && format != "john" && format != "hashcat" {
				return fmt.Errorf("Hash format should be john or hashcat")
			}

			if _, ok := encTypeMapping[strings.ToLower(enctype)]; !ok {
				return fmt.Errorf("enctype value is not valid.")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			tgt, err := krb5.AskTGT(domain, username, password, keyBytes, paramStringToEType(strings.ToLower(enctype)), dcIp, noPac)
			if err != nil {
				return err
			}

			if format == "john" {
				fmt.Printf("%s\n", tgt.JohnString())
			} else if format == "hashcat" {
				fmt.Printf("%s\n", tgt.HashcatString())
			}

			if len(outputFile) > 0 {
				cred := tgt.Credentials()
				if err := cred.SaveToFile(outputFile); err != nil {
					return err
				}

				fmt.Printf("TGT saved to %s.\n", outputFile)
			}

			return nil
		},
	}
	askTgtCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain to target")
	askTgtCmd.Flags().StringVarP(&username, "username", "u", "", "Username of the targeted user")
	askTgtCmd.Flags().StringVarP(&password, "password", "p", "", "Password of the targeted user")
	askTgtCmd.Flags().StringVarP(&key, "key", "k", "", "Secret key of the targeted user (derivated from password)")
	askTgtCmd.Flags().StringVarP(&enctype, "enctype", "e", "aes256", "Encryption type: rc4, aes128 or aes256")
	askTgtCmd.Flags().StringVarP(&dcIp, "dc-ip", "", "", "IP of the KDC (Domain controler)")
	askTgtCmd.Flags().BoolVarP(&noPac, "no-pac", "", false, "Request a TGT without PAC")
	askTgtCmd.Flags().StringVarP(&format, "format", "f", "", "Output hash as John the Ripper or Hashcat format (mode 18200)")
	askTgtCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output the TGT to a kirbi file")

	Command.AddCommand(askTgtCmd)
}
