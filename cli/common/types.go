package common

import (
	"github.com/pterm/pterm"
	"regexp"
)

const PrivateInboxSelector = "_PRIV_INBOX.{{subject()}}.>"

func RequiredTextInput(prompt string) string {
	for {
		value, err := pterm.DefaultInteractiveTextInput.Show(prompt)
		if err != nil {
			panic(err)
		}
		if len(value) > 0 {
			return value
		} else {
			pterm.Warning.Println("Required input - please try again.")
		}
	}
}

func TextInputMatchingRegex(prompt string, regexp *regexp.Regexp) string {
	for {
		value, err := pterm.DefaultInteractiveTextInput.Show(prompt)
		if err != nil {
			panic(err)
		}
		if regexp.Match([]byte(value)) {
			return value
		} else {
			pterm.Warning.Println("Input does not match regex " + regexp.String())
		}

	}
}
