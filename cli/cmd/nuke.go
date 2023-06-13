package cmd

import (
	"github.com/bitfield/script"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
)

func newNukeCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "nuke",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			shouldRemove, err := pterm.DefaultInteractiveConfirm.Show("Do you *REALLY* want to remove all Operators, Accounts, Users and associated NKEYS?")
			panicOnErr(err)
			if !shouldRemove {
				return
			}

			_, err = script.NewPipe().
				// we should never use this directory, so it"s safe to remove.
				Apply(ExecAndStdout(`rm -Rf ~/.local/share/nats/nsc/`)).
				Apply(ExecAndStdout(`rm -Rf ./nsc`)).
				Apply(Printfln(pterm.Success, `All removed`)).
				Apply(ExecAndStdout(`docker compose down`)).
				Stdout()
			panicOnErr(err)
		},
	}
}
