package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePack writes a pack file with the given top-level section and raw rule
// entries. Kept deliberately literal so a test reads as the YAML it exercises.
// Files land in <dir>/community/ because the walk (internal/rulecount) reads
// the four pack directories, not an arbitrary tree.
func writePack(t *testing.T, dir, name, body string) {
	t.Helper()
	name = filepath.Join("community", name)
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeBaseline(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "baseline.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const cleanPack = `
name: clean
rules:
  - id: rule-a
    taxonomy: "k/c/a"
  - id: rule-b
    taxonomy: "k/c/b"
`

func runIn(t *testing.T, packs, baseline string) (int, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(packs, baseline, true, &out, &errw)
	return code, out.String() + errw.String()
}

func TestClean_NoDuplicates_Passes(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	code, _ := runIn(t, d, filepath.Join(d, "absent-baseline.txt"))
	if code != 0 {
		t.Fatalf("clean corpus should pass, got exit %d", code)
	}
}

func TestNewCrossFileDuplicate_Fails(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "b.yaml", "name: b\nrules:\n  - id: rule-a\n    taxonomy: \"k/c/other\"\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 1 {
		t.Fatalf("cross-file duplicate should fail, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "rule-a") || !strings.Contains(out, "NEW") {
		t.Fatalf("expected rule-a reported as NEW:\n%s", out)
	}
}

// THE test for this gate. Comply#3433's collector records each FILE once per
// id, so a verbatim port passes this case while the loaders still double-count.
// Shield has two such pairs today; if this test ever goes green-by-blindness the
// gate is worthless.
func TestNewIntraFileDuplicate_Fails(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", `
name: a
rules:
  - id: rule-a
    taxonomy: "k/c/first"
  - id: rule-b
    taxonomy: "k/c/b"
  - id: rule-a
    taxonomy: "k/c/second"
`)
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 1 {
		t.Fatalf("INTRA-FILE duplicate must fail, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "INTRA-FILE") {
		t.Fatalf("expected the report to name it INTRA-FILE:\n%s", out)
	}
	if !strings.Contains(out, "TAXONOMY DISAGREES") {
		t.Fatalf("expected the taxonomy disagreement to be surfaced:\n%s", out)
	}
}

func TestDuplicateOutsideRulesSection_Fails(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", "name: a\nstructural_rules:\n  - id: sr-1\n    taxonomy: \"k/c/x\"\n")
	writePack(t, d, "b.yaml", "name: b\nstructural_rules:\n  - id: sr-1\n    taxonomy: \"k/c/y\"\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 1 {
		t.Fatalf("structural_rules duplicate must fail, got exit %d\n%s", code, out)
	}
}

func TestBaselinedDuplicate_Passes(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "b.yaml", "name: b\nrules:\n  - id: rule-a\n    taxonomy: \"k/c/other\"\n")
	bl := writeBaseline(t, d, "# grandfathered\n2 rule-a\n")
	code, out := runIn(t, d, bl)
	if code != 0 {
		t.Fatalf("baselined duplicate should pass, got exit %d\n%s", code, out)
	}
}

// The ratchet's second direction: a baseline may only shrink. Without this, the
// file degenerates into a list of excuses nobody ever removes.
func TestBaselinedDuplicateThatDisappeared_Fails(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	bl := writeBaseline(t, d, "2 rule-a\n")
	code, out := runIn(t, d, bl)
	if code != 1 {
		t.Fatalf("resolved duplicate must force a baseline removal, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "FIXED") {
		t.Fatalf("expected a FIXED section:\n%s", out)
	}
}

func TestBaselinedDuplicateThatGrew_Fails(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "b.yaml", "name: b\nrules:\n  - id: rule-a\n    taxonomy: \"k/c/x\"\n")
	writePack(t, d, "c.yaml", "name: c\nrules:\n  - id: rule-a\n    taxonomy: \"k/c/y\"\n")
	bl := writeBaseline(t, d, "2 rule-a\n")
	code, out := runIn(t, d, bl)
	if code != 1 {
		t.Fatalf("a duplicate that grew 2->3 must fail, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "GROWN") {
		t.Fatalf("expected a GROWN section:\n%s", out)
	}
}

func TestUnknownIDBearingSection_IsRefused(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", "name: a\nfuture_rules:\n  - id: rule-z\n    taxonomy: \"k/c/z\"\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 2 {
		t.Fatalf("an unknown id-bearing section must be refused, got exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "future_rules") {
		t.Fatalf("expected the unknown section to be named:\n%s", out)
	}
}

// An empty scan is a claim about the scan, not about the corpus.
func TestEmptyCorpus_RefusesToPass(t *testing.T) {
	d := t.TempDir()
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 2 {
		t.Fatalf("empty corpus must not report a pass, got exit %d\n%s", code, out)
	}
}

func TestDisabledPacksAreSkipped(t *testing.T) {
	d := t.TempDir()
	writePack(t, d, "a.yaml", cleanPack)
	writePack(t, d, "_old.yaml", "name: old\nrules:\n  - id: rule-a\n    taxonomy: \"k/c/x\"\n")
	code, out := runIn(t, d, filepath.Join(d, "absent.txt"))
	if code != 0 {
		t.Fatalf("_-prefixed packs are disabled and must not count, got exit %d\n%s", code, out)
	}
}

func TestMalformedBaseline_IsRefused(t *testing.T) {
	for _, bad := range []string{"rule-a\n", "1 rule-a\n", "2 rule-a\n2 rule-a\n"} {
		d := t.TempDir()
		writePack(t, d, "a.yaml", cleanPack)
		bl := writeBaseline(t, d, bad)
		if code, out := runIn(t, d, bl); code != 2 {
			t.Fatalf("malformed baseline %q must be refused, got exit %d\n%s", bad, code, out)
		}
	}
}

// The real corpus must agree with the checked-in baseline, so the gate cannot
// drift green while the file rots.
func TestRealCorpusMatchesCheckedInBaseline(t *testing.T) {
	code, out := runIn(t, "../../packs", "baseline.txt")
	if code != 0 {
		t.Fatalf("packs/ vs baseline.txt is out of date (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "2 duplicated") {
		t.Logf("duplicate count changed; update this assertion deliberately:\n%s", out)
	}
}
