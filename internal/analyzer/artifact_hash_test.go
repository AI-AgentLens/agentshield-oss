package analyzer

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// writeScript writes a script under cwd/rel with the given content and returns
// its sha256 hex. Built at test time so no executable fixture is checked in.
func writeScript(t *testing.T, cwd, rel, content string) string {
	t.Helper()
	p := filepath.Join(cwd, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func writeManifest(t *testing.T, dir string, entries map[string]string) string {
	t.Helper()
	var b string
	b = "version: \"1.0.0\"\nartifacts:\n"
	for path, sha := range entries {
		b += "  - path: " + path + "\n    sha256: " + sha + "\n"
	}
	p := filepath.Join(dir, "artifacts.yaml")
	if err := os.WriteFile(p, []byte(b), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ctxFor(cwd, command string) *AnalysisContext {
	parsed := shellparse.Parse(command, 2)
	// Best-effort path list: the invoked script token(s). The analyzer also
	// derives candidates from ctx.Parsed, so an empty Paths still works.
	return &AnalysisContext{RawCommand: command, Cwd: cwd, Parsed: parsed}
}

func TestArtifactHash_MismatchAudits(t *testing.T) {
	cwd := t.TempDir()
	declared := writeScript(t, cwd, ".claude/skills/pdf/extract.py", "print('v1')\n")
	mpath := writeManifest(t, cwd, map[string]string{".claude/skills/pdf/extract.py": declared})

	// Tamper: rewrite the script so its on-disk hash diverges from declared.
	writeScript(t, cwd, ".claude/skills/pdf/extract.py", "print('evil')\n")

	a := newArtifactHashAnalyzerFromPath(mpath, "audit")
	if a == nil {
		t.Fatal("analyzer should be configured")
	}
	findings := a.Analyze(ctxFor(cwd, "python3 .claude/skills/pdf/extract.py"))
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Decision != "AUDIT" || f.RuleID != artifactRuleID || f.TaxonomyRef != artifactTaxonomy {
		t.Errorf("unexpected finding: %+v", f)
	}
}

func TestArtifactHash_MismatchBlocksInBlockMode(t *testing.T) {
	cwd := t.TempDir()
	declared := writeScript(t, cwd, "skills/s/run.sh", "#!/bin/sh\necho v1\n")
	mpath := writeManifest(t, cwd, map[string]string{"skills/s/run.sh": declared})
	writeScript(t, cwd, "skills/s/run.sh", "#!/bin/sh\necho tampered\n")

	a := newArtifactHashAnalyzerFromPath(mpath, "block")
	findings := a.Analyze(ctxFor(cwd, "bash skills/s/run.sh"))
	if len(findings) != 1 || findings[0].Decision != "BLOCK" {
		t.Fatalf("expected 1 BLOCK finding, got %+v", findings)
	}
}

func TestArtifactHash_MatchAllows(t *testing.T) {
	cwd := t.TempDir()
	declared := writeScript(t, cwd, "skills/s/run.sh", "#!/bin/sh\necho ok\n")
	mpath := writeManifest(t, cwd, map[string]string{"skills/s/run.sh": declared})

	a := newArtifactHashAnalyzerFromPath(mpath, "audit")
	if f := a.Analyze(ctxFor(cwd, "bash skills/s/run.sh")); len(f) != 0 {
		t.Errorf("matching script must produce no finding, got %+v", f)
	}
}

func TestArtifactHash_ScriptNotInManifestIgnored(t *testing.T) {
	cwd := t.TempDir()
	declared := writeScript(t, cwd, "skills/s/run.sh", "x")
	writeScript(t, cwd, "scripts/other.sh", "#!/bin/sh\necho other\n")
	mpath := writeManifest(t, cwd, map[string]string{"skills/s/run.sh": declared})

	a := newArtifactHashAnalyzerFromPath(mpath, "audit")
	// A script that isn't declared is not this analyzer's concern.
	if f := a.Analyze(ctxFor(cwd, "bash scripts/other.sh")); len(f) != 0 {
		t.Errorf("undeclared script must be ignored, got %+v", f)
	}
}

func TestArtifactHash_MissingFileFailsSafe(t *testing.T) {
	cwd := t.TempDir()
	mpath := writeManifest(t, cwd, map[string]string{"skills/s/gone.sh": "deadbeef"})

	a := newArtifactHashAnalyzerFromPath(mpath, "block")
	// Declared script doesn't exist on disk → cannot confirm tampering → no
	// finding (never a false BLOCK on uncertainty).
	if f := a.Analyze(ctxFor(cwd, "bash skills/s/gone.sh")); len(f) != 0 {
		t.Errorf("missing file must fail safe (no finding), got %+v", f)
	}
}

func TestArtifactHash_NoCwdNoOp(t *testing.T) {
	cwd := t.TempDir()
	declared := writeScript(t, cwd, "skills/s/run.sh", "v1")
	mpath := writeManifest(t, cwd, map[string]string{"skills/s/run.sh": declared})
	writeScript(t, cwd, "skills/s/run.sh", "tampered")

	a := newArtifactHashAnalyzerFromPath(mpath, "audit")
	ctx := ctxFor(cwd, "bash skills/s/run.sh")
	ctx.Cwd = "" // scan/check context — no working directory
	if f := a.Analyze(ctx); len(f) != 0 {
		t.Errorf("no cwd must no-op, got %+v", f)
	}
}

func TestArtifactHash_DisabledWhenNoManifest(t *testing.T) {
	if a := newArtifactHashAnalyzerFromPath("", "audit"); a != nil {
		t.Error("empty manifest path must yield nil analyzer (feature off)")
	}
	if a := newArtifactHashAnalyzerFromPath("/nonexistent/artifacts.yaml", "audit"); a != nil {
		t.Error("unreadable manifest must yield nil analyzer (fail-safe off)")
	}
}

func TestArtifactHash_SubdirCwdSuffixMatch(t *testing.T) {
	// The manifest is repo-relative; the agent runs from a subdirectory and
	// invokes the script by an absolute path. Suffix match still catches it.
	repo := t.TempDir()
	declared := writeScript(t, repo, ".claude/skills/pdf/extract.py", "print('v1')\n")
	mpath := writeManifest(t, repo, map[string]string{".claude/skills/pdf/extract.py": declared})
	writeScript(t, repo, ".claude/skills/pdf/extract.py", "print('evil')\n")

	subdir := filepath.Join(repo, "src")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	absScript := filepath.Join(repo, ".claude/skills/pdf/extract.py")

	a := newArtifactHashAnalyzerFromPath(mpath, "audit")
	f := a.Analyze(ctxFor(subdir, "python3 "+absScript))
	if len(f) != 1 {
		t.Fatalf("suffix match from subdir cwd must fire, got %+v", f)
	}
}

// Multiple candidate paths in one command must report the tampered script
// exactly once (dedup) and ignore the benign flag-valued path.
func TestArtifactHash_DedupAndFlagPathIgnored(t *testing.T) {
	cwd := t.TempDir()
	declared := writeScript(t, cwd, "skills/s/run.py", "v1")
	mpath := writeManifest(t, cwd, map[string]string{"skills/s/run.py": declared})
	writeScript(t, cwd, "skills/s/run.py", "tampered")

	a := newArtifactHashAnalyzerFromPath(mpath, "audit")
	f := a.Analyze(ctxFor(cwd, "python3 skills/s/run.py --config skills/s/run.py"))
	if len(f) != 1 {
		t.Fatalf("same file referenced twice must report once, got %d", len(f))
	}
}
