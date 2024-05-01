package main

import (
	"os"

	"github.com/dariuszSki/ziti-agent-wh/webhook"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"
)

var Version = "development"

func main() {
	rootCmd := &cobra.Command{
		Use:     "app",
		Version: Version,
	}

	rootCmd.AddCommand(webhook.CmdWebhook)

	// NOTE(claudiub): Some tests are passing logging related flags, so we need to be able to
	// accept them. This will also include them in the printed help.
	code := cli.Run(rootCmd)
	os.Exit(code)
}
