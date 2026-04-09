package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/spf13/cobra"
)

var (
	logFilterDecision string
	logFilterFlagged  bool
	logLast           int
	logSummary        bool
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View and filter the audit log",
	Long: `View the AgentShield audit log with filtering and summary options.

Examples:
  agentshield log                        # Show all entries
  agentshield log --last 20              # Show last 20 entries
  agentshield log --decision BLOCK       # Show only blocked commands
  agentshield log --flagged              # Show only flagged (AUDIT) entries
  agentshield log --summary              # Show session summary stats`,
	RunE: logCommand,
}

func init() {
	logCmd.Flags().StringVar(&logFilterDecision, "decision", "", "Filter by decision (ALLOW, AUDIT, BLOCK)")
	logCmd.Flags().BoolVar(&logFilterFlagged, "flagged", false, "Show only flagged entries")
	logCmd.Flags().IntVar(&logLast, "last", 0, "Show last N entries")
	logCmd.Flags().BoolVar(&logSummary, "summary", false, "Show summary statistics")
	rootCmd.AddCommand(logCmd)
}

func logCommand(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	events, err := readAuditLog(cfg.LogPath)
	if err != nil {
		return fmt.Errorf("failed to read audit log: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No audit log entries found.")
		return nil
	}

	// Apply filters
	filtered := filterEvents(events)

	// Apply --last
	if logLast > 0 && logLast < len(filtered) {
		filtered = filtered[len(filtered)-logLast:]
	}

	if logSummary {
		printSummary(events, filtered)
		return nil
	}

	printEvents(filtered)
	return nil
}

func readAuditLog(path string) ([]logger.AuditEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var events []logger.AuditEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 1MB max line — MCP tool calls can be large
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var event logger.AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue // skip malformed lines
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}

func filterEvents(events []logger.AuditEvent) []logger.AuditEvent {
	if logFilterDecision == "" && !logFilterFlagged {
		return events
	}

	var filtered []logger.AuditEvent
	for _, e := range events {
		if logFilterDecision != "" && !strings.EqualFold(e.Decision, logFilterDecision) {
			continue
		}
		if logFilterFlagged && !e.Flagged {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

func printEvents(events []logger.AuditEvent) {
	for _, e := range events {
		ts := formatTimestamp(e.Timestamp)
		icon := decisionIcon(e.Decision)
		flagStr := ""
		if e.Flagged {
			flagStr = " [FLAGGED]"
		}

		fmt.Printf("%s %s %s%s\n", icon, ts, e.DisplayLabel(), flagStr)

		if len(e.TriggeredRules) > 0 {
			fmt.Printf("     Rules: %s\n", strings.Join(e.TriggeredRules, ", "))
		}
		if len(e.Reasons) > 0 {
			for _, r := range e.Reasons {
				fmt.Printf("     Reason: %s\n", r)
			}
		}
		if e.Source != "" {
			fmt.Printf("     Source: %s\n", e.Source)
		}
		if e.Error != "" {
			fmt.Printf("     Error: %s\n", e.Error)
		}
		if e.Cwd != "" {
			fmt.Printf("     Cwd: %s\n", e.Cwd)
		}
		if len(e.MCPArguments) > 0 {
			for k, v := range e.MCPArguments {
				fmt.Printf("     %s: %v\n", k, v)
			}
		}
		fmt.Println()
	}
}

func printSummary(all []logger.AuditEvent, filtered []logger.AuditEvent) {
	totalAll := len(all)
	counts := map[string]int{}
	flaggedCount := 0
	errorCount := 0

	for _, e := range all {
		counts[e.Decision]++
		if e.Flagged {
			flaggedCount++
		}
		if e.Error != "" {
			errorCount++
		}
	}

	fmt.Println("═══════════════════════════════════════════")
	fmt.Println("  AgentShield Audit Summary")
	fmt.Println("═══════════════════════════════════════════")
	fmt.Printf("  Total events:    %d\n", totalAll)
	fmt.Printf("  ALLOW:           %d\n", counts["ALLOW"])
	fmt.Printf("  AUDIT:           %d\n", counts["AUDIT"])
	fmt.Printf("  BLOCK:           %d\n", counts["BLOCK"])
	fmt.Printf("  Errors:          %d\n", errorCount)
	fmt.Println("═══════════════════════════════════════════")

	if len(all) > 0 {
		fmt.Printf("  First event:     %s\n", formatTimestamp(all[0].Timestamp))
		fmt.Printf("  Last event:      %s\n", formatTimestamp(all[len(all)-1].Timestamp))
	}

	// Show blocked commands
	blocked := []logger.AuditEvent{}
	for _, e := range all {
		if e.Decision == "BLOCK" {
			blocked = append(blocked, e)
		}
	}
	if len(blocked) > 0 {
		fmt.Println()
		fmt.Println("  Blocked commands:")
		limit := len(blocked)
		if limit > 10 {
			limit = 10
		}
		for _, e := range blocked[len(blocked)-limit:] {
			fmt.Printf("    %s %s\n", formatTimestamp(e.Timestamp), e.Command)
		}
	}

	fmt.Println()
}

func decisionIcon(decision string) string {
	switch decision {
	case "BLOCK":
		return "\xf0\x9f\x9b\x91" // shield
	case "AUDIT":
		return "\xf0\x9f\x94\x8d" // magnifying glass
	case "ALLOW":
		return "\xe2\x9c\x85" // check mark
	default:
		return "\xe2\x9d\x93" // question mark
	}
}

func formatTimestamp(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Local().Format("2006-01-02 15:04:05")
}
