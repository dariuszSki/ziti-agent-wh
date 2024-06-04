package main

import (
	"os"

	"github.com/spf13/cobra"
	"k8s.io/component-base/cli"
)

var Version = "0.2.0"

func main() {
	rootCmd := &cobra.Command{
		Use:     "app",
		Version: Version,
	}

	rootCmd.AddCommand(CmdWebhook)

	code := cli.Run(rootCmd)
	os.Exit(code)
}
