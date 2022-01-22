package sam

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/sam"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/windows/registry"
)

func DumpSAMCredentialsFromHives(sam, system string, isJson bool) error {
	fmt.Printf("Dump credentials from: %s %s\n", sam, system)

	systemHive, err := registry.NewMemoryHive(system)
	if err != nil {
		return err
	}

	samHive, err := registry.NewMemoryHive(sam)
	if err != nil {
		return err
	}

	return dumpSAMCredential(samHive, systemHive, isJson)
}

func dumpSAMCredential(samHive, systemHive registry.Hive, isJson bool) error {
	system := sam.SystemHive{Hive: systemHive}
	sysKey, err := system.GetSystemKey()
	if err != nil {
		return err
	}

	sam := sam.SamHive{Hive: samHive}
	entries, err := sam.GetHashes(sysKey)
	if err != nil {
		return err
	}

	if isJson {
		o := make(map[string]interface{})
		o["credentials"] = entries

		outputJson, err := utils.PrettyfyJSON(o)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", outputJson)
	} else {
		table := utils.PrintTable(entries)
		fmt.Printf("%s\n", table)
	}

	return nil
}

var Command = &cobra.Command{
	Use:   "sam",
	Short: "Dump credentials in SAM",
	Long:  `Dump credentials in SAM`,
}

func init() {
	var systemPath string
	var samPath string
	var isJson bool

	var hiveCommand = &cobra.Command{
		Use:   "hive",
		Short: "Dump from hive files",
		Long:  `Dump local accounts credentials from SAM and SYSTEM hives (reg save HKLM\{SAM|SYSTEM})`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return DumpSAMCredentialsFromHives(samPath, systemPath, isJson)
		},
	}

	hiveCommand.Flags().StringVarP(&systemPath, "system", "", "", "SYSTEM hive path")
	hiveCommand.Flags().StringVarP(&samPath, "sam", "", "", "SAM hive path")
	hiveCommand.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")

	Command.AddCommand(hiveCommand)
}
