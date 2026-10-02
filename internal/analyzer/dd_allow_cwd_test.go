package analyzer

import "testing"

// TestDdAllowResolvesAgainstCwd covers Codex pass 5 on #3997. Claude Code's
// Bash tool keeps the working directory between calls, so a relative dd target
// is only safe relative to the directory the command actually runs in. The
// hook supplies that directory as AnalysisContext.Cwd.
func TestDdAllowResolvesAgainstCwd(t *testing.T) {
	a := NewStructuralAnalyzer(2)
	tests := []struct {
		name, cwd, command string
		wantAllow          bool
	}{
		{"of=sda from /dev", "/dev", "dd if=/dev/zero of=sda count=1", false},
		{"of=dev/sda from /", "/", "dd if=/dev/zero of=dev/sda count=1", false},
		{"relative stderr redirect from /dev", "/dev", "dd if=/dev/zero of=/tmp/x count=1 2>sda", false},
		{"of=null from /dev is the bit bucket", "/dev", "dd if=/dev/zero of=null count=1", true},
		{"relative file from a project dir", "/home/u/proj", "dd if=/dev/zero of=test.img count=1", true},
		{"relative file with unknown cwd", "", "dd if=/dev/zero of=test.img count=1", true},

		// Descriptor duplication only onto stdout, stderr or a close.
		{"stderr onto an inherited fd 4", "/tmp", "dd if=/dev/zero of=/tmp/x count=0 2>&4", false},
		{"stderr onto stdout", "/tmp", "dd if=/dev/zero of=/tmp/x count=0 2>&1", true},
		{"stdout onto stderr", "/tmp", "dd if=/dev/zero of=/tmp/x count=0 >&2", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command, Cwd: tt.cwd}
			allow := hasRuleID(a.Analyze(ctx), "st-allow-dd-to-file")
			if allow != tt.wantAllow {
				t.Errorf("cwd=%q %q: allow=%v, want %v", tt.cwd, tt.command, allow, tt.wantAllow)
			}
		})
	}
}
