package analyzer

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// mainDdAllow is st-allow-dd-to-file's predicate exactly as it was on main
// before #3994, kept here as the reference the fix must never exceed.
func mainDdAllow(parsed *ParsedCommand) bool {
	for _, seg := range allSegments(parsed) {
		exec := seg.Executable
		if exec == "sudo" && len(seg.Args) > 0 && seg.Args[0] == "dd" {
			exec = "dd"
		}
		if exec != "dd" {
			continue
		}
		var ifPath, ofPath string
		allWords := append([]string{}, seg.Args...)
		for k, v := range seg.Flags {
			if v != "" {
				allWords = append(allWords, k+"="+v)
			}
		}
		for _, w := range allWords {
			if strings.HasPrefix(w, "if=") {
				ifPath = w[3:]
			} else if strings.HasPrefix(w, "of=") {
				ofPath = w[3:]
			}
		}
		normIfPath := normalizeTargetPath(ifPath)
		hasDangerousInput := strings.HasPrefix(normIfPath, "/dev/zero") ||
			strings.HasPrefix(normIfPath, "/dev/urandom") ||
			strings.HasPrefix(normIfPath, "/dev/random")
		if hasDangerousInput && ofPath != "" && !isBlockDevice(ofPath) {
			return true
		}
	}
	return false
}

// ddSubsetProbes are the shapes three Codex passes on #3997 used against the
// check, plus ordinary ones, so the property is exercised beyond the corpus.
var ddSubsetProbes = []string{
	"dd if=/dev/zero of=./test.img bs=1M count=10",
	"dd if=/dev/zero of=/tmp/a; dd if=/dev/zero of=/tmp/b",
	`dd if=/dev/zero "of=/tmp/x" count=0`,
	`dd if=/dev/zero of=/tmp/out 'of=/dev/sda'`,
	"dd if=/dev/zero >/dev/sda; dd if=/dev/zero of=/tmp/x count=0",
	`dd if=/dev/zero >/dev/sda; dd if=/dev/zero "of=/tmp/x" count=0`,
	"printf x | xargs -I{} dd if=/dev/zero of=/dev/sda; dd if=/dev/zero of=/tmp/x count=0",
	`find /tmp -maxdepth 0 -exec dd if=/dev/zero of=/dev/sda \; ; dd if=/dev/zero of=/tmp/x count=0`,
	`{ dd if=/dev/zero "of=/dev/null" count=1; } 2>/dev/sda`,
	"{ dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda",
	"dd if=disk.img of=/dev/sda; dd if=/dev/zero of=/tmp/x count=0",
	"dd if=/dev/zero of=/dev/disk0 bs=1m",
	"cat /dev/zero > /dev/sda; dd if=/dev/zero of=/tmp/x count=0",
	"bash <<EOF\nbash -c 'dd if=/dev/zero of=/dev/sda'\nEOF\ndd if=/dev/zero of=/tmp/x count=0",
	"dd if=/dev/zero of=$OUT count=1",
	"cd /dev && dd if=/dev/zero of=sda",
	"ln -s /dev/sda /tmp/out; dd if=/dev/zero of=/tmp/out",
	"command env -C /dev dd if=/dev/zero of=sda count=1",
	"strace -o /dev/sda dd if=/dev/zero of=/dev/null count=1",
	"dd if=/dev/zero of=/dev/null count=1 && { dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda",
	"dd if=/dev/zero of=/dev/null count=1 < <({ dd if=/dev/zero of=/dev/null count=1; } 2>/dev/sda)",
	`for OUT in /dev/sda; do dd if=/dev/zero of=/dev/null count=1 2>"$OUT"; done`,
	"sudo dd if=/dev/zero of=./x.img count=1",
}

// TestDdAllowIsSubsetOfMain is the guarantee #3997 rests on: the dd ALLOW is
// granted only where main granted it, so no command can move from main's
// BLOCK to an ALLOW through this check. A future change that WIDENS the ALLOW
// (for example, reading operands after quote removal, which an earlier round
// of #3997 did and which Codex showed turned three BLOCKs into ALLOW) fails
// here.
func TestDdAllowIsSubsetOfMain(t *testing.T) {
	a := NewStructuralAnalyzer(2)
	check := &ddOutputTargetCheck{}

	var cmds []string
	for _, tc := range testdata.AllTestCases() {
		cmds = append(cmds, tc.Command)
	}
	cmds = append(cmds, ddSubsetProbes...)

	newAllows, mainAllows, withheld := 0, 0, 0
	for _, cmd := range cmds {
		parsed := a.Parse(cmd)
		if parsed == nil {
			continue
		}
		got := len(check.Check(parsed, cmd)) > 0
		ref := mainDdAllow(parsed)
		if got {
			newAllows++
		}
		if ref {
			mainAllows++
			if !got {
				withheld++
			}
		}
		if got && !ref {
			t.Errorf("ALLOW granted where main did not grant it: %q", cmd)
		}
	}
	// Positive control: the check must still grant the ALLOW it exists for
	// (FP-DISKWR-002 and friends), or "subset" holds vacuously.
	if newAllows == 0 {
		t.Fatalf("the check granted no ALLOW over %d commands; the subset property is vacuous", len(cmds))
	}
	t.Logf("dd ALLOW subset: %d commands, main granted %d, this grants %d (%d withheld), 0 beyond main",
		len(cmds), mainAllows, newAllows, withheld)
}
