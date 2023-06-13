package cmd

import (
	"fmt"
	"github.com/nats-io/jsm.go/natscontext"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
	"os"
	"time"
)

func newAdminUserCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "admin-user",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			operator := OperatorName(os.Getenv("OPERATOR_NAME"))
			account := AccountName(os.Getenv("ACCOUNT_NAME"))

			pterm.Printfln("This script generates a %s for an account valid for %s", bold.Sprint("temporary admin user"), bold.Sprint("24 hours"))
			pterm.Println("")
			pterm.Println("This admin is allowed to wiretap on all subjects, including all inboxes")
			pterm.Println("(which is what normal roles cannot do - they can only read their own responses).")

			pterm.DefaultSection.Println("1) Select account to create admin user for")

			if operator == "" {
				operator = chooseOperator()
			}

			if account == "" {
				pterm.Printfln("Choose an account in operator %s:", bold.Sprint(operator))
				account = chooseAccount(operator)
			}

			cfg.MasterPasswordDecryptor().Unlock()

			accountClaims := readAccount(operator, account)
			accountSkNkey := decryptNkey(getAccountSigningKey(accountClaims), cfg.MasterPasswordDecryptor())

			pterm.DefaultSection.Println("2) Creating admin user")

			user := "admin"
			userNkey, err := nkeys.CreateUser()
			panicOnErr(err)
			userClaims := jwt.NewUserClaims(publicKey(userNkey))
			userClaims.Name = user
			userClaims.IssuerAccount = accountClaims.Subject
			userClaims.SetScoped(false)

			// NOTE: --allow-pub-response is not needed here, because we are allowed to publish on *any* topic.
			userClaims.Permissions.Pub.Allow = []string{">"}
			userClaims.Permissions.Sub.Allow = []string{">"}
			userClaims.Expires = time.Now().Add(24 * time.Hour).Unix()

			encoded, err := userClaims.Encode(accountSkNkey)
			panicOnErr(err)

			userConfig, err := jwt.FormatUserConfig(encoded, seed(userNkey))
			panicOnErr(err)
			panicOnErr(os.MkdirAll(fmt.Sprintf("nsc/nkeys/creds/%s/%s", operator, account), 0755))
			err = os.WriteFile(fmt.Sprintf("nsc/nkeys/creds/%s/%s/%s.creds", operator, account, user), userConfig, 0600)
			panicOnErr(err)

			wd, err := os.Getwd()
			panicOnErr(err)
			credsFile := fmt.Sprintf(`%s/nsc/nkeys/creds/%s/%s/%s.creds`, wd, operator, account, user)
			pterm.Success.Printfln(`Created credentials: %s`, credsFile)

			serverUrl := ""
			if operator == "ROOT_natsv1" {
				// TODO: store in JWT?
				serverUrl = "tls://natsv1.cloud.sandstorm.de:32222"
			}

			contextName := fmt.Sprintf("%s_%s_%s", operator, account, user)
			c, err := natscontext.New(
				contextName,
				false,
				natscontext.WithServerURL(serverUrl),
				natscontext.WithCreds(credsFile),
			)
			panicOnErr(err)
			panicOnErr(c.Save(""))
			panicOnErr(natscontext.SelectContext(contextName))
			//nats --creds=./nsc/nkeys/creds/ROOT_natsv1/SANDSTORM/admin.creds --server tls://natsv1.cloud.sandstorm.de:32222  context save --select natsv1_sandstorm_admin

			pterm.Success.Printfln(`Created and auto-selected nats context: %s. To switch to a different context, run %s`, bold.Sprint(contextName), bold.Sprint("nats context select"))
		},
	}
}
