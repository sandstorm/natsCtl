/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"github.com/sandstorm/natsCtl/cli/config"
	"os"

	"github.com/spf13/cobra"
)

func newAccountCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "account",
		Short: "A brief description of your command",
		Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		Run: func(cmd *cobra.Command, args []string) {
			operator := OperatorName(os.Getenv("OPERATOR_NAME"))
			account := AccountName(os.Getenv("ACCOUNT_NAME"))
			accountDescription := AccountDescription(os.Getenv("ACCOUNT_DESCRIPTION"))

			//setupNsc()

			if operator == "" {
				operator = chooseOperator()
			}

			if account == "" {
				pterm.Println("Account name - our convention is UPPERCASE, f.e. SANDSTORM or MY_CUSTOMER:")
				account = AccountName(common.RequiredTextInput("ACCOUNT_NAME"))
			}

			if accountDescription == "" {
				pterm.Println("Account description (explanatory text)")
				desc, err := pterm.DefaultInteractiveTextInput.Show("ACCOUNT_DESCRIPTION")
				accountDescription = AccountDescription(desc)
				panicOnErr(err)
			}

			pterm.Info.Printfln(bold.Sprint("Specify your Master Password") + " for decrypting the Operator Scoped Signing Key.")
			cfg.MasterPasswordDecryptor().Unlock()
			// make sure we have the most up-to-date JWTs.
			//NscPullInt(operator)
			// we need the operator signing key to create a new account.
			pterm.Info.Printfln(`Decrypting Operator Signing Key`)
			operatorSk := getOperatorSigningKey(operator)
			operatorSkNkey := decryptNkey(operatorSk, cfg.MasterPasswordDecryptor())

			var accClaim *jwt.AccountClaims
			if ExistsAccount(operator, account) {
				accClaim = readAccount(operator, account)
				pterm.Info.Printfln("Updating account %s", account)
			} else {
				// account does not exist.
				pterm.Info.Printfln("Creating account %s", account)
				accountNkey, err := nkeys.CreateAccount()
				panicOnErr(err)
				accClaim = jwt.NewAccountClaims(PublicKey(accountNkey))
				accClaim.Name = string(account)
				// ENABLE WITHOUT LIMIT
				accClaim.Limits.MemoryStorage = -1
				// ENABLE WITHOUT LIMIT
				accClaim.Limits.DiskStorage = -1
				writeAccount(operator, accClaim, operatorSkNkey)
				storeAndEncryptNkey(accountNkey, cfg.MasterPasswordDecryptor())
				pterm.Success.Printfln("Encrypted Account Key %s.", bold.Sprint(PublicKey(accountNkey)))
			}

			accClaim.Description = string(accountDescription)
			// --deny-pub and --deny-sub configures the default_permissions (as in https://docs.nats.io/running-a-nats-service/configuration/securing_nats/authorization)
			// -> this is if users are created directly with this account key (which should never happen, as we always
			// want to use Scoped Signing Keys a.k.a Roles), they don't have any rights.
			accClaim.DefaultPermissions.Pub.Deny = []string{">"}
			accClaim.DefaultPermissions.Sub.Deny = []string{">"}

			// ENSURE UN-SCOPED SIGNING KEY EXISTS (for admin user creation)
			if !hasUnscopedSigningKey(accClaim) {
				pterm.Warning.Printfln("Creating (un-scoped) default account signing key (for admin user generation)")
				signingKey := genAndEncryptAccountSigningKey(cfg.MasterPasswordDecryptor())
				accClaim.SigningKeys.Add(string(signingKey))

				pterm.Success.Printfln("Key created.")
			} else {
				pterm.Success.Printfln("Found un-scoped default account signing key (for admin user generation)")
			}

			writeAccount(operator, accClaim, operatorSkNkey)

			// TODO: DocsFn(operator)
		},
	}
}

func hasUnscopedSigningKey(accClaim *jwt.AccountClaims) bool {
	for _, keyScope := range accClaim.SigningKeys {
		if keyScope == nil {
			return true
		}
	}
	return false
}
