package sam

import (
	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/sam"
)

func init() {
	var windowsDirectory string
	var offlineLsaCmd = &cobra.Command{
		Use:   "offlinelsa",
		Short: "offlinelsa",
		Long:  `offlinelsa`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return sam.EnumerateAccountOffline(windowsDirectory)
		},
	}

	offlineLsaCmd.Flags().StringVarP(&windowsDirectory, "windows-directory", "w", "D:\\Windows", "Windows directory")

	Command.AddCommand(offlineLsaCmd)
}
