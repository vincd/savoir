package lsass

import (
	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/sekurlsa"
	"github.com/vincd/savoir/windows/ntdll"
	"github.com/vincd/savoir/windows/process"
)

func init() {
	var isJson bool
	var dumpKerberosTicket bool

	var miniCmd = &cobra.Command{
		Use:   "process",
		Short: "Use a lsass process memory as input (Windows Only)",
		Long:  `Use a lsass process memory as input (Windows Only)`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ntdll.AskPrivilege(ntdll.SE_DEBUG); err != nil {
				return err
			}

			p, err := process.NewProcessReader("lsass.exe")
			if err != nil {
				return err
			}
			defer p.Close()

			l, err := sekurlsa.NewLsaSrv(p)
			if err != nil {
				return err
			}

			si := systemInfo{
				MajorVersion:          p.MajorVersion,
				MinorVersion:          p.MinorVersion,
				BuildNumber:           uint32(p.BuildNumber()),
				ProcessorArchitecture: p.ProcessorArchitecture().String(),
			}

			return PrintLsassDump(si, l, isJson, dumpKerberosTicket)
		},
	}

	miniCmd.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")
	miniCmd.Flags().BoolVarP(&dumpKerberosTicket, "dump-tickets", "d", false, "Dump Kerberos Tickets to kirbi files")

	Command.AddCommand(miniCmd)
}
