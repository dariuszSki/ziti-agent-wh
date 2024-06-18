package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"
)

var Version = "0.3.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "ziti-agent-wh",
		Version: Version,
	}

	rootCmd.AddCommand(CmdWebhook)

	code := cli.Run(rootCmd)
	os.Exit(code)
}
