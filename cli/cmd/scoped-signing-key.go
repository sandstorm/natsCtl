package cmd

import (
	"fmt"
	"github.com/bitfield/script"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nats-io/jwt/v2"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/sandstorm/natsCtl/cli/ui/permissions"
	"github.com/spf13/cobra"
	"os"
	"time"
)

var defaultResponsePermission = &jwt.ResponsePermission{
	MaxMsgs: 1,
	Expires: 10 * time.Minute,
}

func newScopedSigningKeyCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "scoped-signing-key",
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
			role := RoleName(os.Getenv("ROLE_NAME"))

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
				pterm.Printfln("Specify role name (by convention lowercase)")
				role = chooseOrCreateRole(accountClaims)
			}

			scopedSigningKey := scopedSigningKeyForRole(accountClaims, role)
			if scopedSigningKey != nil {
				pterm.Info.Printfln(`MODIFICATION: Scoped Signing Key with Role %s does already exist (%s). Modifying it.`, role, scopedSigningKey.SigningKey())
			} else {
				scopedSigningKey = jwt.NewUserScope()
				scopedSigningKey.Role = string(role)
				scopedSigningKey.Template.Resp = defaultResponsePermission
			}

			if model, err := tea.NewProgram(permissions.NewModel(scopedSigningKey), tea.WithAltScreen()).Run(); err != nil {
				fmt.Println("Error while running program:", err)
				os.Exit(1)
			} else {
				m := model.(permissions.Model)

				// Publish
				scopedSigningKey.Template.Pub = jwt.Permission{
					Allow: m.Pub(),
				}

				// Subscribe
				scopedSigningKey.Template.Sub = jwt.Permission{
					Allow: m.Sub(),
				}

				// Private Inbox
				if len(scopedSigningKey.Template.Pub.Allow) == 0 {
					// Deny all in case nothing is allowed.
					scopedSigningKey.Template.Pub.Deny = []string{">"}
				}

				// it is allowed to publish to specific subjects. This means the service should also be allowed to receive
				// responses for its requests, in case of request/reply.
				//
				// For confidentiality, we want to configure a private Inbox (https://natsbyexample.com/examples/auth/private-inbox/cli)
				// - so this is what we set up here.
				scopedSigningKey.Template.Sub.Allow = append(scopedSigningKey.Template.Sub.Allow, common.PrivateInboxSelector)
				pterm.Success.Printfln("Because requests are allowed, we auto-configure the private response inbox %s", bold.Sprint(common.PrivateInboxSelector))

				// users (apart from admins) MUST use private inboxes; so we auto-deny the default inbox.
				scopedSigningKey.Template.Sub.Deny = []string{"_INBOX.>"}
				if len(scopedSigningKey.Template.Sub.Allow) == 0 {
					// Deny all in case nothing is allowed.
					scopedSigningKey.Template.Sub.Deny = append(scopedSigningKey.Template.Sub.Deny, ">")
				}

				// Replies
				if m.AllowReply {
					scopedSigningKey.Template.Resp = defaultResponsePermission
					pterm.Success.Printfln("Responses allowed for %s after the request.", bold.Sprint(scopedSigningKey.Template.Resp.Expires))
				} else {
					scopedSigningKey.Template.Resp = nil
				}
			}

			pterm.Info.Printfln("%s for decrypting the NKey for %s", bold.Sprint("Specify your Bitwarden Vault Master Password"), account)
			cfg.MasterPasswordDecryptor().Unlock()

			// scoped signing keys are stored inside the account JWT; so we need the Operator Signing Key to update it.
			operatorSigningKey := getOperatorSigningKey(operator)

			if scopedSigningKey.Key == "" {
				// Scoped Signing Key does not exist, so we need to create a new one (and encrypt it).
				scopedSigningKey.Key = genAndEncryptAccountSigningKey(cfg.MasterPasswordDecryptor()).Key()
				accountClaims.SigningKeys.AddScopedSigner(scopedSigningKey)

				pterm.Success.Printfln("Created and encrypted Scoped Signing Key.")
			} else {
				pterm.Info.Printfln("Updating Scoped Signing Key.")
			}

			writeAccount(operator, accountClaims, decryptNkey(operatorSigningKey, cfg.MasterPasswordDecryptor()))

			setupNsc(operator)
			_, err = script.NewPipe().
				Apply(ExecAndStdout(`nsc describe account "%s"`, account)).
				Stdout()
			panicOnErr(err)

			DocsFn(operator)
		},
	}
}
