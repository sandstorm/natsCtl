package cmd

import (
	"github.com/bitfield/script"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
)

func newPushCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "push",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg.MasterPasswordDecryptor().Unlock()
			operator := chooseOperator()
			setupNsc(operator)

			sysAccountSk := getAccountSigningKey(readAccount(operator, "SYS"))
			nkey := decryptNkey(sysAccountSk, cfg.MasterPasswordDecryptor())
			writeUnencryptedNkey(nkey)
			defer rmUnencryptedNkey(nkey)

			_, err := script.Exec("nsc push -A --diff").Stdout()
			panicOnErr(err)
		},
	}
}
