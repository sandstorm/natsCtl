package cmd

import (
	"bytes"
	"filippo.io/age"
	"filippo.io/age/armor"
	"fmt"
	"github.com/bitfield/script"
	"github.com/muesli/termenv"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"github.com/sandstorm/natsCtl/cli/config"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// To create the AGE key: age-keygen 2>/dev/null | grep SECRET-KEY
func storeAndEncryptNkey(key nkeys.KeyPair, masterPasswordDecryptor config.MasterPasswordDecryptor) {
	pk := PublicKey(key)
	ageIdentity, err := masterPasswordDecryptor.LoadMasterPassword()
	panicOnErr(err)

	ageR := ageIdentityToRecipients(ageIdentity)
	err = os.MkdirAll(filepath.Dir(keyPath(pk)), 0700)
	panicOnErr(err)
	f, err := os.OpenFile(string(keyPath(pk))+".age", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	panicOnErr(err)
	armorWriter := armor.NewWriter(f)
	plaintext, err := age.Encrypt(armorWriter, ageR...)
	panicOnErr(err)

	// do the actual encryption
	s, err := key.Seed()
	panicOnErr(err)
	plaintext.Write(s)

	// close all files
	plaintext.Close()
	armorWriter.Close()
	f.Close()
}

func ageIdentityToRecipients(ageIdentity string) []age.Recipient {
	var ageR []age.Recipient
	ids, err := age.ParseIdentities(strings.NewReader(ageIdentity))
	// taken from age-keygen function convert
	panicOnErr(err)
	for _, id := range ids {
		id, ok := id.(*age.X25519Identity)
		if !ok {
			panic(fmt.Sprintf("internal error: unexpected identity type: %T", id))
		}
		ageR = append(ageR, id.Recipient())
	}
	return ageR
}

func decryptNkey(pubkey Key, masterPassword config.MasterPasswordDecryptor) nkeys.KeyPair {
	ageIdentity, err := masterPassword.LoadMasterPassword()
	panicOnErr(err)

	ageKeys, err := age.ParseIdentities(strings.NewReader(ageIdentity))
	panicOnErr(err)

	f, err := os.OpenFile(string(keyPath(pubkey.Key()))+".age", os.O_RDONLY, 0600)
	panicOnErr(err)
	armorReader := armor.NewReader(f)
	decryptedReader, err := age.Decrypt(armorReader, ageKeys...)
	panicOnErr(err)

	decrypted, err := io.ReadAll(decryptedReader)
	panicOnErr(err)

	keyPair, err := nkeys.FromSeed(decrypted)
	panicOnErr(err)

	return keyPair
}

func getOperatorSigningKey(operator OperatorName) OperatorSigningKey {
	for _, signingKey := range readOperator(operator).SigningKeys {
		return OperatorSigningKey(signingKey)
	}
	panic("No Operator Signing Key found")
}

// getAccountSigningKey returns the UN-SCOPED signing key for the account, if it exists
func getAccountSigningKey(accountClaims *jwt.AccountClaims) AccountSigningKey {
	for key, keyScope := range accountClaims.SigningKeys {
		if keyScope == nil {
			// regular signing keys don't have a scope
			return AccountSigningKey(key)
		}
	}
	panic("No un-scoped account signing key found")
}

func keyPath(pubkey string) string {
	return fmt.Sprintf("nsc/nkeys/keys/%s/%s/%s.nk", pubkey[0:1], pubkey[1:3], pubkey)
}

func writeUnencryptedNkey(nkey nkeys.KeyPair) {
	pk, err := nkey.PublicKey()
	panicOnErr(err)
	s, err := nkey.Seed()
	panicOnErr(err)

	err = os.WriteFile(keyPath(pk), s, 0700)
	panicOnErr(err)
}

func rmUnencryptedNkey(nkey nkeys.KeyPair) {
	pk, err := nkey.PublicKey()
	panicOnErr(err)
	err = os.Remove(keyPath(pk))
	panicOnErr(err)
}

func genAndEncryptAccountSigningKey(masterPasswordDecryptor config.MasterPasswordDecryptor) AccountSigningKey {
	k, err := nkeys.CreateAccount()
	panicOnErr(err)
	storeAndEncryptNkey(k, masterPasswordDecryptor)
	return AccountSigningKey(PublicKey(k))
}

func ExecAndStdout(format string, args ...any) func(p *script.Pipe) *script.Pipe {
	return func(p *script.Pipe) *script.Pipe {
		p = p.Exec(fmt.Sprintf(format, args...)).Filter(StdoutAndContinue)
		p.Wait()
		// after p.Wait, the reader was fully consumed and auto-closing.
		// to prevent the error "io: read/write on closed pipe",
		// we need to re-initialize the reader.
		p.Reader = script.NewReadAutoCloser(strings.NewReader(""))
		return p
	}
}

func StdoutAndContinue(reader io.Reader, _ io.Writer) error {
	_, err := io.Copy(os.Stdout, reader)
	return err
}

func Printfln(prefixPrinter pterm.PrefixPrinter, s string, args ...any) func(p *script.Pipe) *script.Pipe {
	return func(p *script.Pipe) *script.Pipe {
		return p.Filter(func(r io.Reader, w io.Writer) error {
			prefixPrinter.Printfln(s, args...)
			return nil
		})
	}
}

func chooseOperator() OperatorName {
	operators := getOperators()
	if len(operators) == 1 {
		return OperatorName(operators[0])
	}

	operatorName, err := pterm.DefaultInteractiveSelect.
		WithOptions(operators).
		Show()
	panicOnErr(err)
	return OperatorName(operatorName)
}

func getOperators() []string {
	operators, err := script.ListFiles("nsc/store/").
		FilterLine(filepath.Base).
		Slice()
	panicOnErr(err)
	return operators
}

func chooseAccount(operatorName OperatorName) AccountName {
	accountName, err := pterm.DefaultInteractiveSelect.
		WithOptions(getAccounts(operatorName)).
		Show()
	panicOnErr(err)
	return AccountName(accountName)
}

func getAccounts(operatorName OperatorName) []string {
	accounts, err := script.ListFiles(fmt.Sprintf(`nsc/store/%s/accounts`, operatorName)).
		FilterLine(func(s string) string {
			return filepath.Base(s)
		}).
		Slice()
	panicOnErr(err)
	return accounts
}

func chooseOrCreateRole(accountClaims *jwt.AccountClaims) RoleName {
	addRole := "Add new role"
	options := []string{addRole}
	options = append(options, getRoleNames(accountClaims)...)

	selection, err := pterm.DefaultInteractiveSelect.
		WithOptions(options).
		WithDefaultOption(addRole).
		Show()
	panicOnErr(err)
	if selection == addRole {
		return RoleName(common.RequiredTextInput("ROLE_NAME"))
	}
	return RoleName(selection)
}

func getRoleNames(accountClaims *jwt.AccountClaims) []string {
	var roleNames []string
	for _, scope := range accountClaims.SigningKeys {
		if scope != nil {
			if userScope, ok := scope.(*jwt.UserScope); ok {
				if userScope.Role != "" {
					roleNames = append(roleNames, userScope.Role)
				}
			}
		}
	}
	return roleNames
}

func chooseRole(accountClaims *jwt.AccountClaims) RoleName {
	selection, err := pterm.DefaultInteractiveSelect.
		WithOptions(getRoleNames(accountClaims)).
		Show()
	panicOnErr(err)
	return RoleName(selection)
}

func scopedSigningKeyForRole(accountClaims *jwt.AccountClaims, role RoleName) *jwt.UserScope {
	for _, scope := range accountClaims.SigningKeys {
		if userScope, ok := scope.(*jwt.UserScope); ok {
			if RoleName(userScope.Role) == role {
				return userScope
			}
		}
	}
	return nil
}

var bold = pterm.NewStyle(pterm.Bold)

func panicOnErr(err error) {
	if err != nil {
		// NOTE: Panic will STILL call defer; so we can clean up files in main() defer
		panic(err)
	}
}

func readOperator(operator OperatorName) *jwt.OperatorClaims {
	accountJwt, err := os.ReadFile(fmt.Sprintf("nsc/store/%s/%s.jwt", operator, operator))
	panicOnErr(err)
	operatorClaims, err := jwt.DecodeOperatorClaims(string(accountJwt))
	panicOnErr(err)
	return operatorClaims
}

func ExistsAccount(operator OperatorName, account AccountName) bool {
	_, err := os.Stat(fmt.Sprintf("nsc/store/%s/accounts/%s/%s.jwt", operator, account, account))
	return err == nil
}

func readAccount(operator OperatorName, account AccountName) *jwt.AccountClaims {
	accountJwt, err := os.ReadFile(fmt.Sprintf("nsc/store/%s/accounts/%s/%s.jwt", operator, account, account))
	panicOnErr(err)
	accountClaims, err := jwt.DecodeAccountClaims(string(accountJwt))
	panicOnErr(err)
	return accountClaims
}

func writeAccount(operator OperatorName, claims *jwt.AccountClaims, operatorSigningKey nkeys.KeyPair) string {
	encoded, err := claims.Encode(operatorSigningKey)
	panicOnErr(err)
	panicOnErr(os.MkdirAll(fmt.Sprintf("nsc/store/%s/accounts/%s", operator, claims.Name), 0755))
	err = os.WriteFile(fmt.Sprintf("nsc/store/%s/accounts/%s/%s.jwt", operator, claims.Name, claims.Name), []byte(encoded), 0644)
	panicOnErr(err)
	return encoded
}

func writeOperator(operator OperatorName, claims *jwt.OperatorClaims, pair nkeys.KeyPair) string {
	encoded, err := claims.Encode(pair)
	panicOnErr(err)
	panicOnErr(os.MkdirAll(fmt.Sprintf("nsc/store/%s", operator), 0755))
	err = os.WriteFile(fmt.Sprintf("nsc/store/%s/%s.jwt", operator, operator), []byte(encoded), 0644)
	panicOnErr(err)
	return encoded
}

func PublicKey(nkey nkeys.KeyPair) string {
	p, err := nkey.PublicKey()
	panicOnErr(err)
	return p
}

func Seed(nkey nkeys.KeyPair) []byte {
	p, err := nkey.Seed()
	panicOnErr(err)
	return p
}

var output *termenv.Output
var tpl *template.Template

func init() {
	output = termenv.NewOutput(os.Stdout)
	f := output.TemplateFuncs()
	tpl = template.New("tpl").Funcs(f)
}
func PrintlnTemplated(text string) {
	tpl, err := tpl.Parse(text)
	panicOnErr(err)

	var buf bytes.Buffer
	panicOnErr(tpl.Execute(&buf, nil))
	fmt.Println(&buf)
}
