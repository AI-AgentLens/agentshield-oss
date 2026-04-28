package analyzer

import (
	"testing"
)

func TestSemanticAnalyzer_FindDelete(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"find /etc -delete", "find /etc -delete", true},
		{"find /var -delete", "find /var -delete", true},
		{"find . -name '*.tmp' -delete", "find . -name '*.tmp' -delete", false}, // not a system path
		{"find /etc -name '*.conf'", "find /etc -name '*.conf'", false},         // no -delete
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			structural.Analyze(ctx) // populate ctx.Parsed
			findings := semantic.Analyze(ctx)
			hit := hasRuleID(findings, "sem-block-find-delete")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}

func TestSemanticAnalyzer_ShredDevice(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"shred /dev/sda", "shred /dev/sda", true},
		{"shred /dev/nvme0n1", "shred /dev/nvme0n1", true},
		{"shred ./file.txt", "shred ./file.txt", false}, // regular file
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			structural.Analyze(ctx)
			findings := semantic.Analyze(ctx)
			hit := hasRuleID(findings, "sem-block-shred-device")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v", tt.command, hit, tt.wantHit)
			}
		})
	}
}

func TestSemanticAnalyzer_WipefsDevice(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"wipefs -a /dev/sda", "wipefs -a /dev/sda", true},
		{"wipefs /dev/nvme0n1", "wipefs /dev/nvme0n1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			structural.Analyze(ctx)
			findings := semantic.Analyze(ctx)
			hit := hasRuleID(findings, "sem-block-wipefs-device")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v", tt.command, hit, tt.wantHit)
			}
		})
	}
}

func TestSemanticAnalyzer_PythonRmtree(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"python3 rmtree", `python3 -c "import shutil; shutil.rmtree('/')"`, true},
		{"python os.remove", `python -c "import os; os.remove('/etc/passwd')"`, true},
		{"python hello", `python3 -c "print('hello')"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			structural.Analyze(ctx)
			findings := semantic.Analyze(ctx)
			hit := hasRuleID(findings, "sem-block-python-rmtree")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v", tt.command, hit, tt.wantHit)
			}
		})
	}
}

func TestSemanticAnalyzer_PythonForkBomb(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"python fork bomb", `python3 -c "import os; [os.fork() for _ in iter(int, 1)]"`, true},
		{"python normal", `python3 -c "print('hello')"`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			structural.Analyze(ctx)
			findings := semantic.Analyze(ctx)
			hit := hasRuleID(findings, "sem-block-python-fork-bomb")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v", tt.command, hit, tt.wantHit)
			}
		})
	}
}

func TestSemanticAnalyzer_CrontabModify(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()

	tests := []struct {
		name    string
		command string
		wantHit bool
	}{
		{"crontab -e", "crontab -e", true},
		{"crontab file", "crontab mycronfile", true},
		{"crontab -l", "crontab -l", false}, // listing only
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			structural.Analyze(ctx)
			findings := semantic.Analyze(ctx)
			hit := hasRuleID(findings, "sem-audit-crontab-modify")
			if hit != tt.wantHit {
				t.Errorf("command %q: got hit=%v, want %v (findings: %v)",
					tt.command, hit, tt.wantHit, findingIDs(findings))
			}
		})
	}
}
