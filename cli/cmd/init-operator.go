package cmd

import (
	"bytes"
	"fmt"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	nsccmd "github.com/nats-io/nsc/v2/cmd"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"github.com/sandstorm/natsCtl/cli/config"
	"github.com/spf13/cobra"
	"os"
	"regexp"
	"strings"
)

//nolint:funlen
func newInitOperatorCmd(cfg config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "init-operator",
		Short: "Sets up a new NATS operator.",
		Long: `A NATS "operator" is the root configuration element for a NATS cluster.

Only needed once per NATS cluster. 

When you run this command, 
`,
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			operator := OperatorName(os.Getenv("OPERATOR_NAME"))
			natsServerUrl := os.Getenv("NATS_SERVER_URL")
			accountServerUrl := os.Getenv("ACCOUNT_SERVER_URL")

			//////////////////////////////////////////
			pterm.DefaultSection.Println("1) Current NATS keys")
			pterm.Println("We print the current NATS keys so that you get an overview of what is")
			pterm.Println("currently configured. Should normally be empty when running this command.")
			pterm.Println("If not empty, you can use the './dev.sh nuke' command to reset everything.")

			_, err = executeSubCommand("nsc", "list", "keys", "-A")
			if err != nil {
				pterm.Info.Println("No NATS keys found at all - so starting from scratch")
			}

			//////////////////////////////////////////
			pterm.DefaultSection.Printfln("2) Operator Creation and configuration")

			if operator == "" {
				pterm.Println("Operator name - our convention is ROOT_...., so f.e. ROOT_natsv1 or ROOT_local:")
				operator = OperatorName(common.RequiredTextInput("OPERATOR_NAME"))
			}

			// the service URL is the default server URL for connecting
			if natsServerUrl == "" {
				pterm.Println("Specify NATS service URL where this operator will be used:")
				pterm.Println("(required for nsc push and nsc pull). Examples: tls://your.domain:4222")
				natsServerUrl = common.TextInputMatchingRegex("NATS_SERVER_URL", regexp.MustCompile(`^(tls|nats)://`))
			}

			// the service URL is required for "nsc push" and "nsc pull" to work properly.
			if accountServerUrl == "" {
				accountServerUrl = strings.ReplaceAll(natsServerUrl, "tls://", "nats://")
				pterm.Println("NATS account server URL where this operator will be used is derived from NATS_SERVER_URL")
				pterm.Println("(required for nsc push and nsc pull).")
				pterm.Println("NOTE: This must be specified with the nats:// protocol to work, without encryption - so tls:// protocol does NOT work here.")
				pterm.Println("The server needs tls.allowNonTLS: true to work with this.")
				pterm.Printfln("    ACCOUNT_SERVER_URL=", accountServerUrl)
				// TODO: seems that NSC push do not work over TLS for whatever reason :(
			}

			pterm.Info.Printfln("Creating operator %s", bold.Sprint(operator))
			pterm.Info.Printfln("- with signing key")
			pterm.Info.Printfln("- with system account")

			pterm.Info.Printfln("We use a single AGE key to protect all NATS NKEYS except the Root Key")
			pterm.Info.Printfln("This AGE key can be protected via a master key.")
			cfg.MasterPasswordDecryptor().Unlock()

			operatorRootNkey, err := nkeys.CreateOperator()
			panicOnErr(err)
			// we do NOT store the root key, but only print it.

			// to quote the docs: "it is good hygiene to create operators with signing keys."
			operatorSigningNkey, err := nkeys.CreateOperator()
			panicOnErr(err)
			storeAndEncryptNkey(operatorSigningNkey, cfg.MasterPasswordDecryptor())

			// we need a system account (--sys) to be able to push/pull accounts then.
			// we do not need a SYS user for pushing/pulling, because it is auto-created anyway on-demand from the SYS Signing Key when pushing.
			systemAccountNKey, systemAccountSigningNKey, sysClaims := createSystemAccount()
			storeAndEncryptNkey(systemAccountNKey, cfg.MasterPasswordDecryptor())
			storeAndEncryptNkey(systemAccountSigningNKey, cfg.MasterPasswordDecryptor())
			sysClaims.Issuer = publicKey(systemAccountSigningNKey)

			operatorClaims := jwt.NewOperatorClaims(publicKey(operatorRootNkey))
			operatorClaims.Issuer = publicKey(operatorSigningNkey)
			// we want to require signing keys to create accounts (ensures that nobody
			// accidentally uses the root key during normal operations)
			// https://github.com/nats-io/nats-server/blame/d90854a45fe9405198093ab1489f8b3e5e11dcf8/server/jwt.go#L134
			operatorClaims.StrictSigningKeyUsage = true
			operatorClaims.Name = string(operator)
			operatorClaims.SystemAccount = publicKey(systemAccountNKey)
			operatorClaims.AccountServerURL = accountServerUrl
			// this way, we do not need to specify the server URLs when connecting.
			operatorClaims.OperatorServiceURLs = strings.Split(natsServerUrl, ",")
			operatorClaims.SigningKeys.Add(publicKey(operatorSigningNkey))
			operatorJwt := writeOperator(operator, operatorClaims, operatorSigningNkey)
			sysAccountJwt := writeAccount(operator, sysClaims, operatorSigningNkey)

			//////////////////////////////////////////
			pterm.DefaultSection.Println("3) Removing operator Root Keys")

			pterm.Printfln(`
    The public root key is: %s
    Please store the private root key safely. THE FOLLOWING PRINTOUT IS
    THE ONLY COPY; the file is removed directly after the printout.
    Please also store the instructions along with the key.

    -----------------------------------------------
    This is the root key of the NATS operator %s.
    This key is only needed in case the signing key of the operator was compromised or lost,
    and in this case we do *not* need to re-create the NATS cluster (but can issue a new signing key,
    and need to create then new accounts + users).
    To restore it, place it inside the file %s.

    PRIVATE ROOT KEY:

        %s

    -----------------------------------------------
`, bold.Sprint(publicKey(operatorRootNkey)), operator, keyPath(publicKey(operatorRootNkey)), seed(operatorRootNkey))

			//////////////////////////////////////////
			pterm.DefaultSection.Println("4) Encrypting signing key via AGE and bitwarden CLI")

			pterm.Info.Printfln("Operator Signing Key: %s located in %s", publicKey(operatorSigningNkey), keyPath(publicKey(operatorSigningNkey)))

			// TODO: why do we do this, instead of storing each NKEY in bitwarden? We could also do this, but it feels somehow wrong.
			// TODO: age-yubikey maybe would be a good argument. TODO maybe ramdisk?
			pterm.Success.Printfln("Encrypted %s Signing Key.", operator)
			//////////////////////////////////////////
			pterm.DefaultSection.Println("5) Generate Bootstrap NATS config")

			configBuilder := nsccmd.NewNatsResolverConfigBuilder(false)
			_ = configBuilder.SetSystemAccount(publicKey(systemAccountNKey))
			_ = configBuilder.Add([]byte(operatorJwt))
			_ = configBuilder.Add([]byte(sysAccountJwt))

			generatedConfig, err := configBuilder.Generate()
			panicOnErr(err)
			_ = os.WriteFile(fmt.Sprintf("nsc/config-%s.cfg", operator), generatedConfig, 0644)

			pterm.Success.Printfln("Generated NATS config %s. Now, continue with configuring your NATS system.", bold.Sprintf("nsc/config-%s.cfg", operator))

			//DocsFn(operator)
		},
	}
}

func executeSubCommand(cmd ...string) (string, error) {
	rootCmd.SetArgs(cmd)
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	err := rootCmd.Execute()
	return buf.String(), err
}

// createSystemAccount  is taken from // see https://github.com/nats-io/nsc/blob/45f67cca820760edde74dbc1ce0abcaecf4f0986/cmd/init.go#L309
func createSystemAccount() (nkeys.KeyPair, nkeys.KeyPair, *jwt.AccountClaims) {
	var acc nkeys.KeyPair
	var sig nkeys.KeyPair
	var err error
	// create system account, signed by this operator
	if acc, err = nkeys.CreateAccount(); err != nil {
		panic(err)
	}
	if sig, err = nkeys.CreateAccount(); err != nil {
		panic(err)
	}
	sysAccClaim := jwt.NewAccountClaims(publicKey(acc))
	sysAccClaim.Name = "SYS"
	sysAccClaim.SigningKeys.Add(publicKey(sig))
	sysAccClaim.Exports = jwt.Exports{&jwt.Export{
		Name:                 "account-monitoring-services",
		Subject:              "$SYS.REQ.ACCOUNT.*.*",
		Type:                 jwt.Service,
		ResponseType:         jwt.ResponseTypeStream,
		AccountTokenPosition: 4,
		Info: jwt.Info{
			Description: `Request account specific monitoring services for: SUBSZ, CONNZ, LEAFZ, JSZ and INFO`,
			InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
		},
	}, &jwt.Export{
		Name:                 "account-monitoring-streams",
		Subject:              "$SYS.ACCOUNT.*.>",
		Type:                 jwt.Stream,
		AccountTokenPosition: 3,
		Info: jwt.Info{
			Description: `Account specific monitoring stream`,
			InfoURL:     "https://docs.nats.io/nats-server/configuration/sys_accounts",
		},
	}}
	return acc, sig, sysAccClaim
}

func publicKey(nkey nkeys.KeyPair) string {
	p, err := nkey.PublicKey()
	panicOnErr(err)
	return p
}

func seed(nkey nkeys.KeyPair) []byte {
	p, err := nkey.Seed()
	panicOnErr(err)
	return p
}
