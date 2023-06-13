package cmd

import (
	"fmt"
	"github.com/bitfield/script"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"syscall"
)

func newPullCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "pull",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			cfg.MasterPasswordDecryptor().Unlock()
			operator := chooseOperator()

			NscPullInt(operator, cfg.MasterPasswordDecryptor())
		},
	}
}

func NscPullInt(operator OperatorName, masterPasswordDecryptor config.MasterPasswordDecryptor) {
	setupNsc(operator)

	sysAccountSk := getAccountSigningKey(readAccount(operator, "SYS"))
	nkey := decryptNkey(sysAccountSk, masterPasswordDecryptor)
	writeUnencryptedNkey(nkey)
	defer rmUnencryptedNkey(nkey)

	_, err := script.Exec("nsc pull -A").Stdout()
	if err != nil {
		pterm.Warning.Println("Continuing with local JWTs because Pull did not work")
	}
}

func setupNsc(operator OperatorName) {
	workingDir, err := os.Getwd()
	panicOnErr(err)
	panicOnErr(os.Setenv("NKEYS_PATH", workingDir+"/nsc/nkeys"))
	panicOnErr(os.Setenv("NSC_HOME", workingDir+"/nsc/home"))
	panicOnErr(os.MkdirAll(workingDir+"/nsc/nkeys", 0700))

	_, err = script.Exec(fmt.Sprintf("nsc env -s '%s/nsc/store'", workingDir)).String()
	panicOnErr(err)

	if operator != "" {
		_, err = script.Exec(fmt.Sprintf("nsc env -o %s", operator)).String()
		panicOnErr(err)
	}
}

func Nsc() {
	setupNsc("")
	nscPath, err := exec.LookPath("nsc")
	panicOnErr(err)

	args := os.Args[2:]
	err = syscall.Exec(nscPath, append([]string{"nsc"}, args...), os.Environ())
	panicOnErr(err)
}

func NscSwitchOperator() {
	operator := OperatorName(os.Getenv("OPERATOR_NAME"))
	if operator == "" {
		operator = chooseOperator()
	}
	setupNsc(operator)
}
