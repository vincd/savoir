package socks

import (
	"fmt"

	"github.com/spf13/cobra"

	socksv5 "github.com/vincd/savoir/modules/paquet/socks"
)

var Command = &cobra.Command{
	Use:   "socks",
	Short: "Socks commands",
	Long:  `Socks commands`,
}

func init() {
	var host string
	var port int
	var username string
	var password string
	var url string

	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Create a socks server",
		Long:  `Create a socks server`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(url) == 0 {
				url = fmt.Sprintf("socks5://%s:%s@%s:%d", username, password, host, port)
			}

			server, err := socksv5.NewServer()
			if err != nil {
				return err
			}

			if err := server.Serve("tcp", url); err != nil {
				return err
			}

			return nil
		},
	}

	serverCmd.Flags().StringVarP(&host, "host", "H", "0.0.0.0", "Listening address")
	serverCmd.Flags().IntVarP(&port, "port", "p", 1234, "Listening port")
	serverCmd.Flags().StringVarP(&username, "username", "u", "", "Socks user username")
	serverCmd.Flags().StringVarP(&password, "password", "P", "", "Socks user password")
	serverCmd.Flags().StringVarP(&url, "url", "", "", "Socks url: socks5://username:password@0.0.0.0:1234")

	Command.AddCommand(serverCmd)
}
