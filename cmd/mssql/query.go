package mssql

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/modules/paquet/tds"
	"github.com/vincd/savoir/utils"
)

func init() {
	var host string
	var socks string
	var ticket string
	var query string

	var queryCmd = &cobra.Command{
		Use:   "query",
		Short: "Execute SQL query on MSSQL database",
		Long:  `Execute SQL query on MSSQL database`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := tds.NewMSSQL(host, 1433)
			if err != nil {
				return err
			}

			dialer, err := utils.GetDialerWithSocks(socks)
			if err != nil {
				return fmt.Errorf("Cannot create dialer client: %s", err)
			}

			if err := m.Connect(dialer); err != nil {
				return fmt.Errorf("cannot connect to mssql database: %s", err)
			}
			defer m.Close()

			fmt.Printf("[*] Use a kirbi file as credentials\n")
			kirbi, err := krb5.NewKrbCredFromFile(ticket)
			if err != nil {
				return fmt.Errorf("cannot load kirbi: %s", err)
			}

			if err := m.LoginWithKerberos(kirbi.Tickets[0], kirbi.DecryptedEncPart.TicketInfo[0]); err != nil {
				return err
			}

			if err := m.Batch(query); err != nil {
				return err
			}

			return nil
		},
	}

	commandAddMSSQLHostInFlags(queryCmd, &host, &socks)
	queryCmd.Flags().StringVarP(&ticket, "ticket", "t", "", "Kiribi file")
	queryCmd.Flags().StringVarP(&query, "query", "q", "SELECT user_name()", "SQL query")

	Command.AddCommand(queryCmd)
}
