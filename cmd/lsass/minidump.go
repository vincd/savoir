package lsass

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/sekurlsa"
	"github.com/vincd/savoir/windows/minidump"
)

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
				return fmt.Errorf("the file %s does not exists", path)
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
