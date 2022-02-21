package token

import (
	"fmt"

	"github.com/spf13/cobra"
	sys_windows "golang.org/x/sys/windows"

	"github.com/vincd/savoir/modules/windows"
	"github.com/vincd/savoir/modules/windows/process"
)

func tokenElevate(commandLine string) error {
	if err := windows.AskPrivilegeSeDebug(); err != nil {
		return err
	}

	targetSid, err := sys_windows.CreateWellKnownSid(sys_windows.WinLocalSystemSid)
	if err != nil {
		return err
	}

	infos, err := windows.QuerySystemProcessInformation()
	if err != nil {
		return err
	}

	currentProcess, err := process.NewCurrentProcess()
	if err != nil {
		return err
	}
	defer currentProcess.Close()

	currentProcessId := sys_windows.GetCurrentProcessId()

	for _, processInfo := range infos {
		ptid := uint32(processInfo.UniqueProcessID)

		if ptid == 0 || currentProcessId == ptid {
			continue
		}

		p, err := process.NewProcessWithPid(ptid)
		if err != nil {
			continue
		}
		defer p.Close()

		tokenHandle, err := p.GetTokenWithAccess(sys_windows.TOKEN_QUERY | sys_windows.TOKEN_DUPLICATE)
		if err != nil {
			continue
		}
		defer tokenHandle.Close()

		duplicatedToken, err := currentProcess.DuplicateToken(*tokenHandle, *currentProcess)
		if err != nil {
			continue
		}
		defer duplicatedToken.Close()

		tokenUser, err := duplicatedToken.GetTokenUser()
		if err != nil {
			continue
		}

		if !tokenUser.User.Sid.Equals(targetSid) {
			continue
		}

		newDuplicatedToken, err := duplicatedToken.DuplicateTokenEx(sys_windows.TOKEN_QUERY|sys_windows.TOKEN_IMPERSONATE|sys_windows.TOKEN_ASSIGN_PRIMARY|sys_windows.TOKEN_DUPLICATE|sys_windows.TOKEN_ADJUST_DEFAULT|sys_windows.TOKEN_ADJUST_SESSIONID, nil, sys_windows.SecurityAnonymous, sys_windows.TokenPrimary)
		if err != nil {
			return err
		}
		defer newDuplicatedToken.Close()

		// if err := sys_windows.SetThreadToken(nil, newDuplicatedToken); err != nil {
		// 		continue
		// }

		if err := windows.CreateProcessWithToken(*newDuplicatedToken, commandLine); err != nil {
			fmt.Printf("Cannot create process with token: %s\n", err)
			continue
		}

		break
	}

	return nil
}

func init() {
	var exec string

	var tokenElevateCmd = &cobra.Command{
		Use:   "elevate",
		Short: "Create new process with an elevated token",
		Long:  `Search a token for the welk known NT AUTHORITY\Systeme, duplicate it then execute a a command.`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return tokenElevate(exec)
		},
	}

	tokenElevateCmd.Flags().StringVarP(&exec, "exec", "x", "C:\\Windows\\System32\\cmd.exe", "Command to execute")

	Command.AddCommand(tokenElevateCmd)
}
