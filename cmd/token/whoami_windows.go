package token

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vincd/savoir/modules/windows/process"
	"github.com/vincd/savoir/modules/windows/threads"
)

func whoami() error {
	currentProcess, err := process.NewCurrentProcess()
	if err != nil {
		return err
	}
	defer currentProcess.Close()

	processToken, err := currentProcess.GetToken()
	if err != nil {
		return err
	}
	defer processToken.Close()

	fmt.Printf("Process Token: \n")
	if err := processToken.DisplayInformation(); err != nil {
		fmt.Printf("cannot display process token information: %s\n", err)
	}

	currentThread, err := threads.NewCurrentThread()
	if err != nil {
		return err
	}
	defer currentThread.Close()

	threadToken, err := currentThread.GetToken()
	if err != nil {
		return err
	} else if threadToken == nil {
		fmt.Printf("no thread token\n")
		return nil
	}
	defer threadToken.Close()

	fmt.Printf("Thread Token: \n")
	if err := threadToken.DisplayInformation(); err != nil {
		fmt.Printf("cannot display thread token information: %s\n", err)
	}

	return nil
}

func init() {
	var tokenWhoamiCmd = &cobra.Command{
		Use:   "whoami",
		Short: "Display current user informations",
		Long:  `Display current user informations`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return whoami()
		},
	}

	Command.AddCommand(tokenWhoamiCmd)
}
