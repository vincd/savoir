package lsass

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/sekurlsa"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/windows/minidump"
)

var Command = &cobra.Command{
	Use:   "lsass",
	Short: "Dump credentials from lsass",
	Long: `
		Dump credentials from lsass.
		All modules and Architecture/BuildNumber are not supported yet.
		Thanks to @gentilkiwi and @skelsec.
		`,
}

type systemInfo struct {
	MajorVersion          uint32 `json:"major_version"`
	MinorVersion          uint32 `json:"minor_version"`
	BuildNumber           uint32 `json:"build_number"`
	ProcessorArchitecture string `json:"processor_architecture"`
}

func PrintLsassDump(si systemInfo, l *sekurlsa.LsaSrv, isJson bool, dumpKerberosTicket bool) error {
	entries, err := l.ListEntries()
	if err != nil {
		return err
	}

	if isJson {
		o := make(map[string]interface{})
		o["system_info"] = si
		o["credentials"] = entries

		outputJson, err := utils.PrettyfyJSON(o)
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", outputJson)
	} else {
		table := utils.PrintTable(si)
		fmt.Printf("%s\n", table)

		for _, entry := range entries {
			fmt.Printf("--- Find new entry -------------------------------------------------------------\n")
			fmt.Printf("%s", entry)
			fmt.Printf("--------------------------------------------------------------------------------\n\n")
		}
	}

	if dumpKerberosTicket {
		for _, entry := range entries {
			if entry.Kerberos != nil && len(entry.Kerberos.Tickets) > 0 {
				for _, ticket := range entry.Kerberos.Tickets {
					if _, err := ticket.Dump(); err != nil {
						fmt.Printf("%s\n", err)
						continue
					}
				}
			}
		}
	}

	return nil
}

func init() {
	var path string
	var isJson bool
	var dumpKerberosTicket bool

	var miniCmd = &cobra.Command{
		Use:   "minidump",
		Short: "Use a lsass minidump as input",
		Long:  `First create a minidump of lsass (https://security-tips.vincd.com/windows/#dump-lsass-process)`,
		Args: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return fmt.Errorf("The file \"%s\" does not exists.", path)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := minidump.NewMinidump(path)
			if err != nil {
				return err
			}

			l, err := sekurlsa.NewLsaSrv(r)
			if err != nil {
				return err
			}

			si := systemInfo{
				MajorVersion:          r.SystemInfo.MajorVersion,
				MinorVersion:          r.SystemInfo.MinorVersion,
				BuildNumber:           uint32(r.BuildNumber()),
				ProcessorArchitecture: r.ProcessorArchitecture().String(),
			}

			return PrintLsassDump(si, l, isJson, dumpKerberosTicket)
		},
	}

	miniCmd.Flags().StringVarP(&path, "path", "p", "", "Set the minidump path")
	miniCmd.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")
	miniCmd.Flags().BoolVarP(&dumpKerberosTicket, "dump-tickets", "d", false, "Dump Kerberos Tickets to kirbi files")

	Command.AddCommand(miniCmd)
}
