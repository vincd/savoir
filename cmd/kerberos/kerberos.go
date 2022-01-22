package kerberos

import (
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "kerberos",
	Short: "Do some Kerberos stuff",
	Long:  `Kerberos stuff`,
}
