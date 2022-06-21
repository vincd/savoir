package mssql

import (
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "mssql",
	Short: "Interact with MSSQL database",
	Long:  `Interact with MSSQL database`,
}

// Add server host and specify a socksproxy
func commandAddMSSQLHostInFlags(cmd *cobra.Command, host *string, socks *string) {
	cmd.Flags().StringVarP(host, "host", "H", "", "MSSQL server hostname")
	cobra.MarkFlagRequired(cmd.Flags(), "host")
	cmd.Flags().StringVarP(socks, "socks", "", "", "Socks proxy server (host:port)")
}
