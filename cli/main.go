/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"github.com/bitfield/script"
	"github.com/pterm/pterm"
	"github.com/sandstorm/natsCtl/cli/cmd"
	"github.com/sandstorm/natsCtl/cli/config"
	"os"
	"regexp"
)

var nkeyRegexp = regexp.MustCompile(`\.nk$`)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	// CLEANUP: in case the script exits (for whatever reason) remove all private NKeys
	// (except in .creds files for users, as they are useful...)
	defer func() {
		if os.Getenv("SKIP_CLEANUP") == "1" {
			pterm.Warning.Println("Skipped cleanup.")
			return
		}
		script.FindFiles("./nsc").MatchRegexp(nkeyRegexp).ExecForEach("rm {{.}}").Wait()
		pterm.Info.Println("Removed unencrypted nkeys.")
	}()

	cmd.Execute(cfg)
}
