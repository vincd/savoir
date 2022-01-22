package kerberos

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
)

func init() {
	var ticket string
	var kirbi64 string

	var describeCmd = &cobra.Command{
		Use:   "describe",
		Short: "Parse a kirbi file",
		Long:  `Parse a kirbi file`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(ticket) > 0 {
				cred, err := krb5.NewKrbCredFromFile(ticket)
				if err != nil {
					return err
				}

				fmt.Printf("%s\n", cred)
			} else if len(kirbi64) > 0 {
				cred, err := krb5.NewKrbCredFromBase64(kirbi64)
				if err != nil {
					return err
				}

				fmt.Printf("%s\n", cred)
			}

			return nil
		},
	}

	describeCmd.Flags().StringVarP(&ticket, "ticket", "t", "", "Set the kirbi file path")
	describeCmd.Flags().StringVarP(&kirbi64, "kirbi", "k", "", "Inline kirbi base64 encoded string")

	Command.AddCommand(describeCmd)
}
