package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "0.1.0-dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print AgentShield version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("AgentShield %s\n", Version)
		fmt.Printf("  Commit: %s\n", GitCommit)
		fmt.Printf("  Built:  %s\n", BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
