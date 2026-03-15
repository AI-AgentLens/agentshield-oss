package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/logger"
	"github.com/security-researcher-ca/agentshield/internal/normalize"
	"github.com/security-researcher-ca/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

var shellMode bool
var verbose bool

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command> [args...]",
	Short: "Run a command through AgentShield",
	Long: `Run a command through AgentShield's policy enforcement layer.
The command and its arguments should be provided after --.

Examples:
  agentshield run -- echo "hello world"
  agentshield run --policy ./custom.yaml -- npm install lodash
  agentshield run --shell -- "echo hello | grep hello"`,
	RunE: runCommand,
}

func init() {
	runCmd.Flags().BoolVar(&shellMode, "shell", false, "Treat args as a shell command string (handles pipes, redirects, etc.)")
	runCmd.Flags().BoolVar(&verbose, "verbose", false, "Show which rules triggered the decision")
	// DISABLED: run command removed from CLI — AgentShield should make decisions (block/audit/allow), not execute commands.
	// rootCmd.AddCommand(runCmd)
}

func runCommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command provided. Usage: agentshield run -- <command> [args...]")
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	auditLogger, err := logger.New(cfg.LogPath)
	if err != nil {
		return fmt.Errorf("failed to initialize audit logger: %w", err)
	}
	defer func() {
		_ = auditLogger.Close()
	}()

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "unknown"
	}

	// In shell mode, join all args into one command string for evaluation.
	// The raw command is what the policy engine sees.
	cmdStr := strings.Join(args, " ")

	// Normalize command
	normalized := normalize.Normalize(args, cwd)

	// Load base policy
	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Merge enabled policy packs
	packsPath := filepath.Join(cfg.ConfigDir, "packs")
	pol, _, err = policy.LoadPacks(packsPath, pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load packs: %v\n", err)
	}

	engine, err := policy.NewEngineWithAnalyzers(pol, cfg.Analyzer.MaxParseDepth)
	if err != nil {
		return fmt.Errorf("failed to create policy engine: %w", err)
	}

	// Evaluate policy with extracted paths
	evalResult := engine.Evaluate(cmdStr, normalized.Paths)

	event := logger.AuditEvent{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Command:        cmdStr,
		Args:           args,
		Cwd:            cwd,
		Decision:       string(evalResult.Decision),
		TriggeredRules: evalResult.TriggeredRules,
		Reasons:        evalResult.Reasons,
		Mode:           cfg.Mode,
	}

	// Handle decision
	switch evalResult.Decision {
	case policy.DecisionBlock:
		fmt.Fprintln(os.Stderr, "\n\xf0\x9f\x9b\x91 BLOCKED by AgentShield")
		fmt.Fprintln(os.Stderr, evalResult.Explanation)
		if verbose && len(evalResult.TriggeredRules) > 0 {
			fmt.Fprintln(os.Stderr, "Triggered rules:")
			for i, rule := range evalResult.TriggeredRules {
				reason := ""
				if i < len(evalResult.Reasons) {
					reason = ": " + evalResult.Reasons[i]
				}
				fmt.Fprintf(os.Stderr, "  [%d] %s%s\n", i+1, rule, reason)
			}
		}
		if err := auditLogger.Log(event); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
		}
		os.Exit(1)

	case policy.DecisionAudit, policy.DecisionAllow:
		// Both AUDIT and ALLOW execute the command.
		// AUDIT adds a flag marker in the log for review.
		if evalResult.Decision == policy.DecisionAudit {
			event.Flagged = true
			if verbose {
				fmt.Fprintf(os.Stderr, "⚑ FLAGGED for review: %s\n", evalResult.Explanation)
			}
		}

		var execCmd *exec.Cmd
		if shellMode {
			execCmd = exec.Command("sh", "-c", cmdStr)
		} else {
			execCmd = exec.Command(args[0], args[1:]...)
		}
		execCmd.Stdin = os.Stdin
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr

		execErr := execCmd.Run()
		if execErr != nil {
			event.Error = execErr.Error()
		}

		if err := auditLogger.Log(event); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to write audit log: %v\n", err)
		}

		if execErr != nil {
			if exitErr, ok := execErr.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return execErr
		}
	}

	return nil
}
