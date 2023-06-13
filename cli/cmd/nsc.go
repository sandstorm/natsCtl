/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/nats-io/nsc/v2/cmd"
)

func init() {
	rootCmd.AddCommand(cmd.GetRootCmd())
}
