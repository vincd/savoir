package scanner

import (
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "scanner",
	Short: "Scan a target",
	Long:  `Scan a target for various thing like TCP services.`,
}
