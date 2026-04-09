package main

import (
	"fmt"
	"os"

	"github.com/AI-AgentLens/agentshield/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
