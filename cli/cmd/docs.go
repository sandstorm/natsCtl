package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/bitfield/script"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

func newDocsCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "docs",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			DocsFn("TODO")
		},
	}
}

func DocsFn(operator OperatorName) {
	setupNsc(operator)

	_, err := script.NewPipe().
		Apply(ExecAndStdout(`rm -Rf nsc/docs`)).
		Apply(ExecAndStdout(`mkdir nsc/docs`)).
		Stdout()
	panicOnErr(err)

	b := strings.Builder{}
	for _, o := range getOperators() {
		operator := OperatorName(o)

		b.WriteString(fmt.Sprintf("# Account overview for %s\n\n", operator))

		for _, a := range getAccounts(operator) {
			account := AccountName(a)

			b.WriteString(fmt.Sprintf("## %s\n\n", account))
			b.WriteString(fmt.Sprintf("[Details](./%s.md)\n\n", account))
			b.WriteString("```\n")

			data := pterm.TableData{
				{"Role", "Permissions", "Key"},
			}

			lines, err := script.Exec(fmt.Sprintf(`nsc describe account --name "%s" -J`, account)).
				JQ(`(.nats.signing_keys[] | if (type == "string") then ["", "", .] else [.role, (.template | tostring), .key] end)?`).
				Slice()
			panicOnErr(err)
			for _, line := range lines {
				var tblRow []string
				panicOnErr(json.Unmarshal([]byte(line), &tblRow))
				data = append(data, tblRow)
			}

			t := pterm.TablePrinter{}.WithData(data).WithWriter(&b).WithSeparator(" | ").WithHeaderRowSeparator("-").WithHasHeader(true)
			panicOnErr(t.Render())

			b.WriteString("```\n\n")

			_, err = script.Exec(fmt.Sprintf(`nsc describe account --name "%s"`, account)).
				WriteFile(fmt.Sprintf(`nsc/docs/%s.md`, account))
			panicOnErr(err)
		}
	}

	err = os.WriteFile(fmt.Sprintf("nsc/docs/README.md"), []byte(b.String()), 0644)
	panicOnErr(err)
}
