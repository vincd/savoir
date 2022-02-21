package token

import (
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "token",
	Short: "Manipulate Windows tokens",
	Long:  `Manipulate Windows tokens`,
}
