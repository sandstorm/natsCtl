package cmd

import (
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
	"os"
)

func newDecryptNkeyCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt-nkey",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			pterm.Printfln("nkey to decrypt")
			key := AccountKey(common.RequiredTextInput("NKEY"))
			cfg.MasterPasswordDecryptor().Unlock()
			keypair := decryptNkey(key, cfg.MasterPasswordDecryptor())

			err := os.WriteFile(keyPath(publicKey(keypair)), seed(keypair), 0600)
			panicOnErr(err)
		},
	}
}
