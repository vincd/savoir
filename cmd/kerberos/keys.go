package kerberos

import (
	"encoding/binary"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
)

func printKey(eType int32, password string, salt string, s2kp string) {
	et, err := crypto.NewEType(eType)
	if err != nil {
		fmt.Printf("[!] Cannot get Encryption Type: %s\n", err)
	}

	key, err := et.GenerateSecretkey(password, salt, string(s2kp))
	if err != nil {
		fmt.Printf("[!] Cannot generate key for EType: %s\n", crypto.ETypeToString(et.GetEtype()))
	}

	fmt.Printf("%s\n", crypto.ETypeToString(et.GetEtype()))
	fmt.Printf("  Key: %x\n", key)
	fmt.Printf("  Iterations: %x\n", s2kp)
	fmt.Printf("\n")
}

func init() {
	var password string
	var salt string
	var iterations int

	var kerberosKeysCmd = &cobra.Command{
		Use:   "keys",
		Short: "Computes Kerberos keys",
		Long:  `Computes Kerberos keys from a given password using Kerberos version 5 Key Derivation Functions (RC4_HMAC, AES128_CTS_HMAC_SHA1_96 and AES256_CTS_HMAC_SHA1_96).`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			s2kp := make([]byte, 4)
			binary.BigEndian.PutUint32(s2kp, uint32(iterations))

			printKey(crypto.RC4_HMAC, password, salt, string(s2kp))
			printKey(crypto.AES128_CTS_HMAC_SHA1_96, password, salt, string(s2kp))
			printKey(crypto.AES256_CTS_HMAC_SHA1_96, password, salt, string(s2kp))
			// TODO: DES_CBC_MD5

			return nil
		},
	}

	kerberosKeysCmd.Flags().StringVarP(&password, "password", "p", "", "Specifies an input password from which kerberos keys will be derived")
	kerberosKeysCmd.Flags().StringVarP(&salt, "salt", "s", "", "Specifies the salt parameter of the string-to-key functions")
	kerberosKeysCmd.Flags().IntVarP(&iterations, "iterations", "i", 4096, "Specifies the iteration count parameter of the string-to-key functions")

	Command.AddCommand(kerberosKeysCmd)
}
