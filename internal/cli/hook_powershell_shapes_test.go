package cli

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/route"
)

// The 12 PowerShell attack shapes of #4245 (internal/psreader/testdata/
// corpora/corpus-attack.jsonl) on the three rows the PowerShell lane is on,
// through the real hook entry point. ADR-001 step 5 added the PowerShell
// pack rules (packs/community/powershell.yaml); each row below records main's
// decision before step 5 (fe86ae40) and the decision and kept rule after.
// Adding rules may only raise.
//
// The shapes are read from the corpus file, not written here: the hook on a
// developer machine reads test sources it is asked to run as commands.
//
// Two shapes keep AUDIT on purpose: the fork bomb (no enumerable signature)
// and the home delete (bash decides AUDIT too). The encoded command is AUDIT
// by decision: the lane decodes it and the decoded text decides. The env
// exfil and encoded command AUDITs tie with the row's earlier lane, whose
// AUDIT names no rule, so the PowerShell lane's record is the receipt and
// names its rule (the AUDIT tie rule, Gary 2026-11-05, #4779; before it the
// rule was named in the lane_readings note only).
//
// The native-command bridge (#4768, on all three rows) changes none of the
// 12: they are cmdlets, except schtasks, whose bridge reading BLOCKs by
// ts-block-schtasks-create and ties with ps-block-schtasks-create (the
// lane's own record is kept; on the Copilot rows POSIX's BLOCK is earlier
// and keeps its), and powershell -EncodedCommand, whose text is routed to
// this lane, not bridged.

type psShapeRow struct {
	main     string // decision on main before step 5
	decision string
	rule     string // a rule id the kept record must carry; "" = none in particular
	// laneRule is the PowerShell lane's first rule, as the lane_readings
	// note names it; "" = the note names none.
	laneRule string
}

// psShapeRows: shape id -> row -> expectation.
var psShapeRows = map[string]map[string]psShapeRow{
	"00-home-delete": {
		"claude-code": {main: "AUDIT", decision: "AUDIT"},
		"compat":      {main: "AUDIT", decision: "AUDIT"},
		"native":      {main: "AUDIT", decision: "AUDIT"},
	},
	"01-format-disk": {
		"claude-code": {main: "AUDIT", decision: "BLOCK", rule: "ps-block-format-volume", laneRule: "ps-block-format-volume"},
		"compat":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-format-volume", laneRule: "ps-block-format-volume"},
		"native":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-format-volume", laneRule: "ps-block-format-volume"},
	},
	"02-cred-read": {
		"claude-code": {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
		"compat":      {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
		"native":      {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
	},
	"03-key-exfil": {
		"claude-code": {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
		"compat":      {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
		"native":      {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
	},
	"04-env-exfil": {
		"claude-code": {main: "AUDIT", decision: "AUDIT", rule: "ps-audit-env-exfil", laneRule: "ps-audit-env-exfil"},
		"compat":      {main: "AUDIT", decision: "AUDIT", rule: "ps-audit-env-exfil", laneRule: "ps-audit-env-exfil"},
		"native":      {main: "AUDIT", decision: "AUDIT", rule: "ps-audit-env-exfil", laneRule: "ps-audit-env-exfil"},
	},
	"05-download-exec": {
		"claude-code": {main: "AUDIT", decision: "BLOCK", rule: "ps-block-download-exec", laneRule: "ps-block-download-exec"},
		"compat":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-download-exec", laneRule: "ps-block-download-exec"},
		"native":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-download-exec", laneRule: "ps-block-download-exec"},
	},
	"06-encoded-cmd": {
		"claude-code": {main: "AUDIT", decision: "AUDIT", rule: "ps-audit-encoded-command", laneRule: "ps-audit-encoded-command"},
		"compat":      {main: "AUDIT", decision: "AUDIT", rule: "ps-audit-encoded-command", laneRule: "ps-audit-encoded-command"},
		"native":      {main: "AUDIT", decision: "AUDIT", rule: "ps-audit-encoded-command", laneRule: "ps-audit-encoded-command"},
	},
	"07-sched-persist": {
		"claude-code": {main: "AUDIT", decision: "BLOCK", rule: "ps-block-schtasks-create", laneRule: "ps-block-schtasks-create"},
		// POSIX's ts-block-schtasks-create BLOCKed it on main; the tie keeps
		// POSIX's record
		"compat": {main: "BLOCK", decision: "BLOCK", rule: "ts-block-schtasks-create", laneRule: "ps-block-schtasks-create"},
		"native": {main: "BLOCK", decision: "BLOCK", rule: "ts-block-schtasks-create", laneRule: "ps-block-schtasks-create"},
	},
	"08-history-wipe": {
		"claude-code": {main: "AUDIT", decision: "BLOCK", rule: "ps-block-history-psreadline-wipe", laneRule: "ps-block-history-psreadline-wipe"},
		"compat":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-history-psreadline-wipe", laneRule: "ps-block-history-psreadline-wipe"},
		"native":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-history-psreadline-wipe", laneRule: "ps-block-history-psreadline-wipe"},
	},
	"09-disable-av": {
		"claude-code": {main: "AUDIT", decision: "BLOCK", rule: "ps-block-defender-disable", laneRule: "ps-block-defender-disable"},
		"compat":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-defender-disable", laneRule: "ps-block-defender-disable"},
		"native":      {main: "AUDIT", decision: "BLOCK", rule: "ps-block-defender-disable", laneRule: "ps-block-defender-disable"},
	},
	"10-fork-bomb": {
		"claude-code": {main: "AUDIT", decision: "AUDIT"},
		"compat":      {main: "AUDIT", decision: "AUDIT"},
		"native":      {main: "AUDIT", decision: "AUDIT"},
	},
	"11-key-read": {
		"claude-code": {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
		"compat":      {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
		"native":      {main: "BLOCK", decision: "BLOCK", rule: "protected-path", laneRule: "protected-path"},
	},
}

// psAttackShapes reads the 12 shapes.
func psAttackShapes(t *testing.T) map[string]string {
	t.Helper()
	path := filepath.Join("..", "psreader", "testdata", "corpora", "corpus-attack.jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var row struct{ ID, Command string }
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out[row.ID] = row.Command
	}
	return out
}

func TestPowerShellLane_AttackShapes(t *testing.T) {
	shapes := psAttackShapes(t)
	if len(shapes) != 12 || len(psShapeRows) != 12 {
		t.Fatalf("%d shapes in the corpus, %d expected rows: want 12 of each", len(shapes), len(psShapeRows))
	}
	copilotOnWindows := append([]string{"AGENTSHIELD_AGENT_ID=copilot-cli"}, onWindows...)
	rows := []struct {
		key     string
		payload func(cmd string) string
		env     []string
		lane    string // the lane_readings note's tool
	}{
		{"claude-code", func(cmd string) string { return claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(cmd), nil) }, nil, "PowerShell"},
		{"compat", func(cmd string) string { return copilotCompatPayload(t, "ps-shapes", "Bash", shellArgs(cmd)) }, copilotOnWindows, "Bash"},
		{"native", func(cmd string) string { return copilotNativePayload(t, "ps-shapes", "powershell", shellArgs(cmd)) }, nil, "powershell"},
	}
	blocks := map[string][2]int{} // row -> main, now
	for id, cmd := range shapes {
		want, ok := psShapeRows[id]
		if !ok {
			t.Fatalf("shape %q has no expected row", id)
		}
		for _, r := range rows {
			w := want[r.key]
			if route.Rank(route.Verdict{Decision: w.decision}) < route.Rank(route.Verdict{Decision: w.main}) {
				t.Errorf("%s on %s: expectation %s is below main's %s; step 5 may only raise", id, r.key, w.decision, w.main)
			}
			n := blocks[r.key]
			if w.main == "BLOCK" {
				n[0]++
			}
			if w.decision == "BLOCK" {
				n[1]++
			}
			blocks[r.key] = n
			t.Run(id+"/"+r.key, func(t *testing.T) {
				home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
				_, _, stderr := runHookChild(t, home, r.payload(cmd), r.env...)
				events := routingEvents(t, configDir)
				if len(events) != 1 {
					t.Fatalf("want one audit event, got %d: %+v (stderr %s)", len(events), events, stderr)
				}
				e := events[0]
				if e.Decision != w.decision {
					t.Errorf("decision %s %v, want %s (main %s)", e.Decision, e.TriggeredRules, w.decision, w.main)
				}
				if w.rule != "" && !slices.Contains(e.TriggeredRules, w.rule) {
					t.Errorf("rules %v lack %s", e.TriggeredRules, w.rule)
				}
				var readings string
				for _, note := range e.Notes {
					if note.Kind == "lane_readings" {
						readings = note.Detail
					}
				}
				psPart := "powershell=" + w.decision
				if w.laneRule != "" {
					psPart = "(" + w.laneRule + ")"
				}
				if !strings.Contains(readings, psPart) {
					t.Errorf("lane_readings %q lack %q", readings, psPart)
				}
			})
		}
	}
	t.Logf("BLOCK of 12 (main -> step 5): claude-code PowerShell %v, Copilot Bash on Windows %v, Copilot native powershell %v",
		blocks["claude-code"], blocks["compat"], blocks["native"])
}
