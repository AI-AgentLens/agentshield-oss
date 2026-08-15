package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// logState builds one on-disk audit log shape under home and returns the
// substring the Audit chain line must contain, plus how it counts.
type logState struct {
	name string
	// build writes the log; a no-op build means "no log file at all".
	build       func(t *testing.T, path string)
	wantSubstr  string
	wantPassed  bool
	wantCounted bool
}

func chainLogStates() []logState {
	return []logState{
		{
			name:        "no log yet",
			build:       func(*testing.T, string) {},
			wantSubstr:  "no entries yet",
			wantPassed:  false,
			wantCounted: false,
		},
		{
			name:        "legacy log written before chaining shipped",
			build:       func(t *testing.T, path string) { writeUnchainedEntries(t, path, 3) },
			wantSubstr:  "unprotected",
			wantPassed:  false,
			wantCounted: true,
		},
		{
			name: "mixed log: unchained prefix then a live chain",
			build: func(t *testing.T, path string) {
				writeUnchainedEntries(t, path, 2)
				writeChainedEntries(t, path, 3)
			},
			wantSubstr:  "partially protected",
			wantPassed:  false,
			wantCounted: true,
		},
		{
			name:        "fully chained log",
			build:       func(t *testing.T, path string) { writeChainedEntries(t, path, 4) },
			wantSubstr:  "verified (4 entries)",
			wantPassed:  true,
			wantCounted: true,
		},
		{
			name: "tampered log",
			build: func(t *testing.T, path string) {
				writeChainedEntries(t, path, 4)
				tamperWithEntry(t, path, 2)
			},
			wantSubstr:  "broken at entry 2",
			wantPassed:  false,
			wantCounted: true,
		},
	}
}

// TestTamperSection_ChainVerifiedInEveryMode is the fitness function for issue
// #3134: the audit chain is written by every install, but `scan` only verified
// it in managed mode, so most installs produced tamper-evidence that nothing
// ever read.
//
// It runs the real states against real log files, in both modes, and asserts
// both the rendered line and the effect on the summary counters.
func TestTamperSection_ChainVerifiedInEveryMode(t *testing.T) {
	for _, managed := range []bool{false, true} {
		mode := "non-managed"
		if managed {
			mode = "managed"
		}
		t.Run(mode, func(t *testing.T) {
			basePassed, baseTotal := -1, -1

			for _, st := range chainLogStates() {
				t.Run(st.name, func(t *testing.T) {
					cfg := tamperTestConfig(t, managed)
					st.build(t, cfg.LogPath)

					out, passed, total := captureTamperSection(t, cfg)

					line := auditChainLine(out)
					if line == "" {
						t.Fatalf("no Audit chain line in %s mode — the chain was not verified\n%s", mode, out)
					}
					if !strings.Contains(line, st.wantSubstr) {
						t.Errorf("line %q does not contain %q", line, st.wantSubstr)
					}
					if !st.wantPassed && strings.Contains(line, "✅") {
						t.Errorf("line %q renders a green tick for a non-passing state", line)
					}

					// "no log yet" is the first state and asserts nothing
					// either way, so it doubles as the per-mode baseline.
					if baseTotal < 0 {
						basePassed, baseTotal = passed, total
						if !managed && (passed != 0 || total != 0) {
							t.Fatalf("non-managed baseline should run no checks, got %d/%d", passed, total)
						}
					}

					wantTotal, wantPassed := 0, 0
					if st.wantCounted {
						wantTotal = 1
						if st.wantPassed {
							wantPassed = 1
						}
					}
					if got := total - baseTotal; got != wantTotal {
						t.Errorf("total delta = %d, want %d (a counted check must move the denominator)", got, wantTotal)
					}
					if got := passed - basePassed; got != wantPassed {
						t.Errorf("passed delta = %d, want %d", got, wantPassed)
					}
					if passed > total {
						t.Errorf("passed %d > total %d — the summary would report more passes than checks", passed, total)
					}
				})
			}
		})
	}
}

// TestTamperSection_FailingChainRaisesTheDenominator locks the bug shape #3119
// fixed: a failing check must enlarge `total`, never shrink it. If a failure
// drops out of the denominator instead, the scan summary still reports
// "All N tests passed" while a check is red.
func TestTamperSection_FailingChainRaisesTheDenominator(t *testing.T) {
	cfg := tamperTestConfig(t, false)
	writeChainedEntries(t, cfg.LogPath, 3)
	tamperWithEntry(t, cfg.LogPath, 1)

	_, passed, total := captureTamperSection(t, cfg)

	if total != 1 {
		t.Errorf("total = %d, want 1 — a broken chain must be counted, not skipped", total)
	}
	if passed != 0 {
		t.Errorf("passed = %d, want 0", passed)
	}
	if failed := total - passed; failed != 1 {
		t.Errorf("failed = %d, want 1 — the summary would not report the broken chain", failed)
	}
}

// TestTamperSection_UsesConfiguredLogPath guards the path the check reads.
// Outside managed mode `--log` is honoured, so rebuilding the path from
// ConfigDir would verify a file the install never writes to and report
// "no entries yet" forever — a silent no-op dressed as a check.
func TestTamperSection_UsesConfiguredLogPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTSHIELD_BYPASS", "")

	elsewhere := filepath.Join(t.TempDir(), "custom-audit.jsonl")
	cfg, err := config.Load("", elsewhere, "enforce")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.LogPath != elsewhere {
		t.Fatalf("LogPath = %q, want the --log override %q", cfg.LogPath, elsewhere)
	}
	writeChainedEntries(t, elsewhere, 2)

	// A decoy at the default location, so reading the wrong file is visible.
	if err := os.MkdirAll(cfg.ConfigDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeUnchainedEntries(t, filepath.Join(cfg.ConfigDir, "audit.jsonl"), 9)

	out, passed, total := captureTamperSection(t, cfg)
	line := auditChainLine(out)
	if !strings.Contains(line, "verified (2 entries)") {
		t.Errorf("line %q — expected the chain at the configured --log path", line)
	}
	if passed != 1 || total != 1 {
		t.Errorf("passed/total = %d/%d, want 1/1", passed, total)
	}
}

// ── helpers ──────────────────────────────────────────────────────────

func tamperTestConfig(t *testing.T, managed bool) *config.Config {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AGENTSHIELD_BYPASS", "")

	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if managed {
		body := []byte(`{"managed":true,"organization_id":"org-test"}`)
		if err := os.WriteFile(filepath.Join(dir, "managed.json"), body, 0o600); err != nil {
			t.Fatalf("write managed.json: %v", err)
		}
	}

	cfg, err := config.Load("", "", "enforce")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func captureTamperSection(t *testing.T, cfg *config.Config) (string, int, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w

	passed, total := printTamperProtection(cfg)

	os.Stdout = orig
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	_ = r.Close()
	return string(out), passed, total
}

func auditChainLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Audit chain:") {
			return l
		}
	}
	return ""
}

// writeChainedEntries appends genuinely chained entries via the production
// logger, so the fixture cannot drift from how the chain is really written.
func writeChainedEntries(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	lg, err := logger.New(path)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	defer func() { _ = lg.Close() }()
	for i := 0; i < n; i++ {
		if err := lg.Log(logger.AuditEvent{
			Timestamp: "2026-07-28T00:00:0" + string(rune('0'+i%10)) + "Z",
			Command:   "ls",
			Args:      []string{"-la"},
			Decision:  "ALLOW",
			Mode:      "enforce",
		}); err != nil {
			t.Fatalf("log entry %d: %v", i, err)
		}
	}
}

// writeUnchainedEntries appends records with no chain fields — what a build
// that predates the hash chain left behind.
func writeUnchainedEntries(t *testing.T, path string, n int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	for i := 0; i < n; i++ {
		data, err := json.Marshal(logger.AuditEvent{
			Timestamp: "2026-01-01T00:00:00Z",
			Command:   "echo",
			Decision:  "ALLOW",
			Mode:      "enforce",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

// tamperWithEntry rewrites the command of one record in place, leaving its
// stored entry_hash behind — exactly what an in-place edit looks like.
func tamperWithEntry(t *testing.T, path string, idx int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if idx >= len(lines) {
		t.Fatalf("entry %d out of range (%d entries)", idx, len(lines))
	}
	var entry logger.ChainedEvent
	if err := json.Unmarshal([]byte(lines[idx]), &entry); err != nil {
		t.Fatalf("unmarshal entry %d: %v", idx, err)
	}
	entry.Command = "rewritten-by-the-agent"
	edited, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	lines[idx] = string(edited)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
