package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// The README is a trust surface: a buyer or auditor reads its harness claims.
// CLAUDE.md "Harness-support claims" allows the chokepoint claim and forbids the
// universal one, because the support matrix has deliberate holes (Windsurf, Gemini
// CLI and OpenClaw have no MCP interception; OpenClaw has no shell evaluation).
// #4586 fixed one false OpenClaw claim and pinned the shipped hook text; nothing
// pinned the README itself, so a later edit could bring the universal claim back
// with every test green.

func readmeLower(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ToLower(string(b))
}

func readmeFlat(t *testing.T) string {
	t.Helper()
	return regexp.MustCompile(`\s+`).ReplaceAllString(readmeLower(t), " ")
}

func TestReadme_MakesNoUniversalHarnessClaim(t *testing.T) {
	text := readmeFlat(t)
	for _, claim := range []string{
		"all agent frameworks",
		"all frameworks",
		"all harnesses",
		"every harness",
		"all ides",
		"every ide",
		"shell and mcp on every",
		"works with every agent",
		"works with any agent",
	} {
		if strings.Contains(text, claim) {
			t.Errorf("README makes the universal claim %q; use the two-chokepoints claim", claim)
		}
	}
}

func TestReadme_KeepsTheChokepointClaimAndTheMatrixHoles(t *testing.T) {
	// The published tree swaps in README_oss.md (scripts/publish-oss.sh), which
	// has neither the chokepoint sentence nor a support matrix, so there is
	// nothing to pin there. The universal-claim ban above still runs on it.
	if !ossbuild.PremiumPacksPresent() {
		t.Skip("OSS tree: README is README_oss.md, which has no support matrix")
	}
	text := readmeFlat(t)
	// Positive control: the sentence the checks above are protecting still exists,
	// so a rewording that dropped it cannot leave the negative test vacuously green.
	if !strings.Contains(text, "two chokepoints every agent framework converges on") {
		t.Error("README lost the two-chokepoints sentence")
	}
	var openclaw string
	for _, line := range strings.Split(readmeLower(t), "\n") {
		if strings.HasPrefix(line, "| **openclaw**") {
			openclaw = line
		}
	}
	if openclaw == "" {
		t.Fatal("README support matrix has no OpenClaw row")
	}
	if !strings.Contains(openclaw, "nothing is evaluated or blocked") {
		t.Errorf("OpenClaw row must say nothing is evaluated: %q", openclaw)
	}
}
