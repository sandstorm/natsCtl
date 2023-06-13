package cmd

import (
	"fmt"
	"github.com/nats-io/jsm.go/natscontext"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
	"os"
)

func newUserCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "user",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			operator := OperatorName(os.Getenv("OPERATOR_NAME"))
			account := AccountName(os.Getenv("ACCOUNT_NAME"))
			role := RoleName(os.Getenv("ROLE_NAME"))
			user := UserName(os.Getenv("USER_NAME"))

			pterm.DefaultSection.Println("1) Select Scoped Signing Key")

			if operator == "" {
				operator = chooseOperator()
			}

			if account == "" {
				pterm.Printfln("Choose an account in operator %s:", bold.Sprint(operator))
				account = chooseAccount(operator)
			}
			accountClaims := readAccount(operator, account)

			if role == "" {
				pterm.Printfln("Choose role to create a user for")
				role = chooseRole(accountClaims)
			}

			if user == "" {
				pterm.Printfln("User name to create (by convention lowercase)")
				user = UserName(common.RequiredTextInput("USER_NAME"))
			}

			scopedSk := scopedSigningKeyForRole(accountClaims, role)
			if scopedSk == nil {
				panic(fmt.Errorf("no scoped signing key found for role %s - should never happen", role))
			}
			pterm.Success.Printfln("Using scoped signing key %s (%s/%s) for creating user.", scopedSk.SigningKey(), account, role)

			pterm.Info.Printfln("%s for decrypting the NKey for %s", bold.Sprint("Specify your Bitwarden Vault Master Password"), account)
			cfg.MasterPasswordDecryptor().Unlock()
			scopedSkNkey := decryptNkey(ScopedSigningKey(scopedSk.Key), cfg.MasterPasswordDecryptor())

			userNkey, err := nkeys.CreateUser()
			panicOnErr(err)
			userClaims := jwt.NewUserClaims(publicKey(userNkey))
			userClaims.Name = string(user)
			userClaims.SetScoped(true)
			userClaims.IssuerAccount = accountClaims.Subject

			encoded, err := userClaims.Encode(scopedSkNkey)
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
			pterm.Success.Printfln(`Inbox Prefix: %s`, bold.Sprintf(InboxPrefix(publicKey(userNkey))))

			pterm.Success.Printfln(`❗️In your client application, you need to configure a custom %s as stated above.`, bold.Sprint("Inbox Prefix"))
			pterm.Success.Printfln(`❗️for CLI usage, use %s ...`, bold.Sprintf("nats --inbox-prefix=%s", InboxPrefix(publicKey(userNkey))))
			pterm.Success.Printfln(`KUBERNETES Secret: %s`, bold.Sprintf("kubectl create secret generic nats-creds --from-file=auth.creds=./nsc/nkeys/creds/%s/%s/%s.creds --from-literal=NATS_INBOX_PREFIX=%s", operator, account, user, InboxPrefix(publicKey(userNkey))))

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
			//nats --creds=./nsc/nkeys/creds/ROOT_natsv1/SANDSTORM/admin.creds --server tls://natsv1.cloud.sandstorm.de:32222  context save --select natsv1_sandstorm_admin

			pterm.Success.Printfln(`Created nats context: %s. To select, run %s`, bold.Sprint(contextName), bold.Sprint("nats context select"))
		},
	}
}
