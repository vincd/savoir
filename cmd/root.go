package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/vincd/savoir/cmd/kerberos"
	"github.com/vincd/savoir/cmd/ldap"
	"github.com/vincd/savoir/cmd/lsass"
	"github.com/vincd/savoir/cmd/mssql"
	"github.com/vincd/savoir/cmd/sam"
	"github.com/vincd/savoir/cmd/scanner"
	"github.com/vincd/savoir/cmd/socks"
	"github.com/vincd/savoir/cmd/token"
	"github.com/vincd/savoir/cmd/webscreenshot"
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/logger"
)

var rootCmd = &cobra.Command{
	Use:   utils.AppVersion.Name,
	Short: utils.AppVersion.ShortLine(),
	Long:  utils.AppVersion.LongLine(),
}

func addVersionCommand() {
	var isJson bool

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Display version",
		Args: func(cmd *cobra.Command, args []string) error {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if isJson {
				outputJson, err := utils.PrettyfyJSON(utils.AppVersion)
				if err != nil {
					return err
				}
				fmt.Printf("%s\n", outputJson)
			} else {
				fmt.Printf(utils.AppVersion.Extended())
			}

			return nil
		},
	}

	versionCmd.Flags().BoolVarP(&isJson, "json", "j", false, "Print output as a JSON object")

	rootCmd.AddCommand(versionCmd)
}

func addSubCommands() {
	rootCmd.AddCommand(kerberos.Command)
	rootCmd.AddCommand(ldap.Command)
	rootCmd.AddCommand(sam.Command)
	rootCmd.AddCommand(scanner.Command)
	rootCmd.AddCommand(socks.Command)
	rootCmd.AddCommand(lsass.Command)
	rootCmd.AddCommand(mssql.Command)
	rootCmd.AddCommand(token.Command)
	rootCmd.AddCommand(webscreenshot.Command)

	addVersionCommand()

	viper.SetEnvPrefix(utils.AppVersion.Name)
	viper.BindEnv("logger-level", "SAVOIR_LOGGER_LEVEL")
	logger.UpdateDefaultLogLevel(viper.GetString("logger-level"))
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	addSubCommands()

	cobra.OnInitialize(initConfig)
}

func initConfig() {
	viper.AutomaticEnv()
}
