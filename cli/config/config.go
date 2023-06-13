package config

import (
	"encoding/json"
	"errors"
	"filippo.io/age"
	"fmt"
	"github.com/bitfield/script"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/common"
	"os"
	"os/exec"
)

const NatsUtilsConfigFile = "natsUtilsCfg.json"

const typeEnvVar = "EnvVar"
const typeBitwarden = "Bitwarden"

func LoadConfig() (Config, error) {
	var config Config
	file, err := os.ReadFile(NatsUtilsConfigFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			BootstrapConfig()
			return LoadConfig()
		}
		return config, err
	}
	err = json.Unmarshal(file, &config)
	if err != nil {
		return config, fmt.Errorf("malformed JSON in %s: %w", NatsUtilsConfigFile, err)
	}
	return config, nil
}

func BootstrapConfig() {
	pterm.DefaultSection.Println("Creating " + NatsUtilsConfigFile + " file.")

	pterm.Println("We protect all NKEYS with a single master-key by using AGE-Encryption.")
	pterm.Println("This master key can be configured via environment variables (not recommended),")
	pterm.Println("or loaded from Bitwarden password manager (recommended).")
	pterm.Println("")
	pterm.Println("How do you want to store the master key?")
	pterm.Println("")

	keyStoreType, err := pterm.DefaultInteractiveSelect.
		WithOptions([]string{
			typeEnvVar,
			typeBitwarden,
		}).
		Show()
	if err != nil {
		panic(err)
	}

	pterm.Println("You can either re-use an existing AGE key, or we can create a new one.")
	pterm.Println("For your convenience, here is a new AGE private key:")
	pterm.Printfln("")
	k, err := age.GenerateX25519Identity()
	if err != nil {
		panic(err)
	}
	pterm.Printfln("       Private Key (store safely):")
	pterm.Printfln("       %s", k)
	pterm.Printfln("")

	c := Config{}
	switch keyStoreType {
	case typeEnvVar:
		pterm.Println("You need to store the private AGE Key in an environment variable MASTER_KEY")
		pterm.Println("before calling any operation.")
		c.MasterPassword = MasterPasswordConfig{
			Type: typeEnvVar,
		}
	case typeBitwarden:
		pterm.Println("You need to store the private AGE Key in Bitwarden as password.")
		pterm.Println("Then you need the 'bw' CLI tool installed, and you need to specify")
		pterm.Println("the name of the Bitwarden entry of the private key:")
		pterm.Println("")
		entryName := common.RequiredTextInput("Bitwarden Entry Name")

		c.MasterPassword = MasterPasswordConfig{
			Type:                    typeBitwarden,
			BitwardenVaultEntryName: entryName,
		}
	}

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(err)
	}

	pterm.Println("")
	pterm.Printfln("Writing %s", NatsUtilsConfigFile)
	err = os.WriteFile(NatsUtilsConfigFile, b, 0644)
	if err != nil {
		panic(err)
	}
}

type MasterPasswordDecryptor interface {
	// Unlock unlocks the keychain. Can be interactive.
	Unlock()
	// LoadMasterPassword loads the master password after Unlock() is called
	LoadMasterPassword() (string, error)
}
type MasterPasswordConfig struct {
	Type                    string `json:"type"`
	BitwardenVaultEntryName string `json:"bitwardenVaultEntryName"`
}

type Config struct {
	MasterPassword          MasterPasswordConfig `json:"masterPassword"`
	masterPasswordDecryptor MasterPasswordDecryptor
}

func (c *Config) MasterPasswordDecryptor() MasterPasswordDecryptor {
	if c.masterPasswordDecryptor == nil {
		switch c.MasterPassword.Type {
		case typeBitwarden:
			return &bitwardenDecryptor{
				bitwardenVaultEntryName: c.MasterPassword.BitwardenVaultEntryName,
			}
		case typeEnvVar:
			return &bitwardenDecryptor{
				bitwardenVaultEntryName: c.MasterPassword.BitwardenVaultEntryName,
			}
		default:
			panic(fmt.Sprintf("!!! Master password config type '%s' not supported; only supported: %s %s", c.MasterPassword.Type, typeBitwarden, typeEnvVar))
		}
	}
	return c.masterPasswordDecryptor
}

type bitwardenDecryptor struct {
	bitwardenVaultEntryName string
}

func (b *bitwardenDecryptor) Unlock() {
	if len(os.Getenv("BW_SESSION")) > 0 {
		// already unlocked
		return
	}
	cmd := exec.Command("bw", "unlock", "--raw")
	cmd.Stdin = os.Stdin
	//cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	bwSession, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	err = os.Setenv("BW_SESSION", string(bwSession))
	if err != nil {
		panic(err)
	}
}

func (b *bitwardenDecryptor) LoadMasterPassword() (string, error) {
	return script.Exec(`bw get password "` + b.bitwardenVaultEntryName + `"`).
		String()
}
